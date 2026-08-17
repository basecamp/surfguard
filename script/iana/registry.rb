# frozen_string_literal: true

require "digest"
require "ipaddr"
require "json"
require "socket"

module Surfguard
  module Iana
    class Error < StandardError; end

    IP_VERSION_BY_FAMILY = {
      Socket::AF_INET => 4,
      Socket::AF_INET6 => 6
    }.freeze
    IANA_XML_NAMESPACE = "http://www.iana.org/assignments"

    Schema = Struct.new(
      :id, :snapshot_file, :source_url, :metadata_url, :metadata_registry_id, :headers,
      :prefix_header, :family, :selection, :statuses,
      keyword_init: true
    )
    Prefix = Struct.new(:cidr, :family, :integer, :prefix, keyword_init: true) do
      def tuple
        [ IP_VERSION_BY_FAMILY.fetch(family), integer, prefix ].freeze
      end
    end
    Snapshot = Struct.new(
      :schema, :registry_updated, :source_sha256, :semantic_sha256, :prefixes,
      keyword_init: true
    )

    SCHEMA_VERSION = 1
    SNAPSHOT_KEYS = %w[
      schema_version registry url metadata_url registry_updated source_sha256
      selection semantic_sha256 prefixes
    ].sort.freeze

    IPV4_SPECIAL_HEADERS = [
      "Address Block", "Name", "RFC", "Allocation Date", "Termination Date",
      "Source", "Destination", "Forwardable", "Globally Reachable", "Reserved-by-Protocol"
    ].freeze
    IPV6_ALLOCATED_HEADERS = [ "Prefix", "Designation", "Date", "WHOIS", "RDAP", "Status", "Note" ].freeze

    SCHEMAS = [
      Schema.new(
        id: "ipv4_special_use",
        snapshot_file: "ipv4_special_use.json",
        source_url: "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv",
        metadata_url: "https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xml",
        metadata_registry_id: "iana-ipv4-special-registry",
        headers: IPV4_SPECIAL_HEADERS,
        prefix_header: "Address Block",
        family: Socket::AF_INET,
        selection: :all,
        statuses: nil
      ),
      Schema.new(
        id: "ipv6_allocated",
        snapshot_file: "ipv6_allocated.json",
        source_url: "https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.csv",
        metadata_url: "https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xml",
        metadata_registry_id: "ipv6-unicast-address-assignments",
        headers: IPV6_ALLOCATED_HEADERS,
        prefix_header: "Prefix",
        family: Socket::AF_INET6,
        selection: :status_allocated,
        statuses: %w[ALLOCATED RESERVED].freeze
      ),
      Schema.new(
        id: "ipv6_special_use",
        snapshot_file: "ipv6_special_use.json",
        source_url: "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv",
        metadata_url: "https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xml",
        metadata_registry_id: "iana-ipv6-special-registry",
        headers: IPV4_SPECIAL_HEADERS,
        prefix_header: "Address Block",
        family: Socket::AF_INET6,
        selection: :all,
        statuses: nil
      )
    ].each do |schema|
      schema.id.freeze
      schema.snapshot_file.freeze
      schema.source_url.freeze
      schema.metadata_url.freeze
      schema.metadata_registry_id.freeze
      schema.headers.freeze
      schema.freeze
    end.freeze
    SCHEMAS_BY_ID = SCHEMAS.to_h { |schema| [ schema.id, schema ] }.freeze

    module Registry
      module_function

      def schema(id)
        SCHEMAS_BY_ID.fetch(id.to_s) { raise Error, "unknown IANA registry schema #{id.inspect}" }
      end

      def load_snapshots(directory)
        actual = Dir[File.join(directory, "*.json")].map { |path| File.basename(path) }.sort
        expected = SCHEMAS.map(&:snapshot_file).sort
        raise Error, "IANA snapshot files differ: expected #{expected.inspect}, got #{actual.inspect}" unless actual == expected

        SCHEMAS.to_h do |entry|
          path = File.join(directory, entry.snapshot_file)
          [ entry.id, parse_snapshot(entry.id, File.binread(path)) ]
        end.freeze
      end

      def parse_snapshot(id, bytes)
        entry = schema(id)
        text = utf8_string(bytes, "#{id}: snapshot is not valid UTF-8")
        data = JSON.parse(text, allow_duplicate_key: true)
        reject_duplicate_json_keys!(text, id)
        raise Error, "#{id}: snapshot must be a JSON object" unless Hash === data
        raise Error, "#{id}: snapshot fields differ" unless data.keys.sort == SNAPSHOT_KEYS
        raise Error, "#{id}: unsupported snapshot schema" unless data["schema_version"] == SCHEMA_VERSION
        raise Error, "#{id}: registry identity differs" unless data["registry"] == entry.id
        raise Error, "#{id}: source URL differs from the code-owned schema" unless data["url"] == entry.source_url
        unless data["metadata_url"] == entry.metadata_url
          raise Error, "#{id}: metadata URL differs from the code-owned schema"
        end
        raise Error, "#{id}: selector differs from the code-owned schema" unless data["selection"] == entry.selection.to_s

        updated = owned_string(data["registry_updated"], "#{id}: invalid registry update date")
        raise Error, "#{id}: invalid registry update date" unless valid_iso_date?(updated)
        source_sha = digest_string(data["source_sha256"], "#{id}: invalid source SHA-256")
        semantic_sha = digest_string(data["semantic_sha256"], "#{id}: invalid semantic SHA-256")
        prefixes = records_from_cidrs(entry, data["prefixes"], context: "#{id} snapshot")
        actual_semantic_sha = semantic_digest(prefixes)
        unless actual_semantic_sha == semantic_sha
          raise Error, "#{id}: semantic SHA-256 does not match the normalized prefixes"
        end

        Snapshot.new(
          schema: entry,
          registry_updated: updated.freeze,
          source_sha256: source_sha.freeze,
          semantic_sha256: semantic_sha.freeze,
          prefixes: prefixes
        ).freeze
      rescue JSON::ParserError => error
        raise Error, "#{id}: malformed snapshot JSON: #{error.message}"
      end

      def parse_registry(entry, bytes)
        bytes = utf8_string(bytes, "#{entry.id}: registry body is not valid UTF-8")

        headers, rows = parse_csv(bytes, id: entry.id)
        unless headers == entry.headers
          raise Error, "#{entry.id}: registry headers differ: #{headers.inspect}"
        end

        cidrs = []
        rows.each_with_index do |values, index|
          unless values.length == headers.length
            raise Error, "#{entry.id}: row #{index + 2} has #{values.length} fields; expected #{headers.length}"
          end
          row = headers.zip(values).to_h
          if entry.selection == :status_allocated
            status = row["Status"]
            unless entry.statuses.include?(status)
              raise Error, "#{entry.id}: row #{index + 2} has unknown status #{status.inspect}"
            end
            next unless status == "ALLOCATED"
          elsif entry.selection != :all
            raise Error, "#{entry.id}: unknown code-owned selector #{entry.selection.inspect}"
          end

          cidrs.concat(prefix_tokens(row[entry.prefix_header], entry.id, index + 2))
        end
        raise Error, "#{entry.id}: registry selection is empty" if cidrs.empty?

        records_from_cidrs(entry, cidrs, context: "#{entry.id} registry")
      end

      def records_from_cidrs(entry, values, context:)
        raise Error, "#{context}: prefixes must be an array" unless Array === values

        seen = {}
        values.map.with_index do |value, index|
          cidr = owned_string(value, "#{context}: prefix #{index + 1} must be a string")
          record = parse_cidr(entry, cidr, context: "#{context}: prefix #{index + 1}")
          duplicate = seen[record.tuple]
          raise Error, "#{context}: duplicate prefix #{cidr.inspect} (already #{duplicate.inspect})" if duplicate

          seen[record.tuple] = cidr
          record
        end.freeze
      end

      def parse_cidr(entry, cidr, context:)
        match = /\A([^\/]+)\/(0|[1-9]\d*)\z/.match(cidr)
        raise Error, "#{context}: invalid CIDR #{cidr.inspect}" unless match

        address_text = match[1]
        prefix = Integer(match[2], 10)
        address = IPAddr.new(address_text)
        unless address.family == entry.family
          raise Error, "#{context}: wrong address family for #{cidr.inspect}"
        end
        bits = IP_VERSION_BY_FAMILY.fetch(entry.family) == 4 ? 32 : 128
        raise Error, "#{context}: invalid prefix length for #{cidr.inspect}" unless (0..bits).cover?(prefix)

        mask = prefix.zero? ? 0 : (((1 << prefix) - 1) << (bits - prefix))
        network_integer = address.to_i & mask
        raise Error, "#{context}: host bits are set in #{cidr.inspect}" unless network_integer == address.to_i

        canonical = "#{render_address(entry.family, network_integer)}/#{prefix}"
        raise Error, "#{context}: non-canonical CIDR #{cidr.inspect}; expected #{canonical}" unless cidr == canonical

        Prefix.new(cidr: cidr.freeze, family: entry.family, integer: network_integer, prefix: prefix).freeze
      rescue IPAddr::InvalidAddressError, ArgumentError
        raise Error, "#{context}: invalid CIDR #{cidr.inspect}"
      end

      def semantic_digest(records)
        Digest::SHA256.hexdigest(JSON.generate(records.map(&:tuple)))
      end

      def registry_updated(bytes, id: "IANA metadata")
        bytes = utf8_string(bytes, "#{id}: metadata body is not valid UTF-8")
        expected_registry_id = SCHEMAS_BY_ID[id]&.metadata_registry_id
        updated = parse_registry_metadata_xml(bytes, id, expected_registry_id)
        raise Error, "#{id}: expected exactly one registry update date" unless updated.one?
        date = updated.first
        raise Error, "#{id}: invalid registry update date" unless valid_iso_date?(date)

        String.new(date).freeze
      end

      def parse_csv(bytes, id: "IANA registry")
        raise Error, "#{id}: registry CSV has no header row" if bytes.empty?

        rows = []
        row = []
        field = +""
        quoted = false
        after_quote = false
        index = 0
        ended_with_record_separator = false

        while index < bytes.length
          character = bytes[index]
          if quoted
            if character == '"'
              if bytes[index + 1] == '"'
                field << '"'
                index += 2
              else
                quoted = false
                after_quote = true
                index += 1
              end
            else
              field << character
              index += 1
            end
            next
          end

          if after_quote && character != "," && character != "\n" && character != "\r"
            raise Error, "#{id}: malformed CSV after closing quote"
          end

          case character
          when '"'
            raise Error, "#{id}: quote appears inside an unquoted CSV field" unless field.empty? && !after_quote

            quoted = true
            index += 1
          when ","
            row << field
            field = +""
            after_quote = false
            ended_with_record_separator = false
            index += 1
          when "\n", "\r"
            if character == "\r"
              raise Error, "#{id}: bare carriage return in CSV" unless bytes[index + 1] == "\n"
              index += 1
            end
            row << field
            rows << row
            row = []
            field = +""
            after_quote = false
            ended_with_record_separator = true
            index += 1
          else
            field << character
            ended_with_record_separator = false
            index += 1
          end
        end
        raise Error, "#{id}: unterminated quoted CSV field" if quoted

        unless ended_with_record_separator
          row << field
          rows << row
        end
        [ rows.first.freeze, rows.drop(1).map(&:freeze).freeze ].freeze
      end

      def render_address(family, integer)
        return [ integer ].pack("N").unpack("C4").join(".") if family == Socket::AF_INET

        hextets = 8.times.map { |index| (integer >> ((7 - index) * 16)) & 0xffff }
        best_start = nil
        best_length = 0
        index = 0
        while index < hextets.length
          unless hextets[index].zero?
            index += 1
            next
          end

          finish = index
          finish += 1 while finish < hextets.length && hextets[finish].zero?
          length = finish - index
          if length >= 2 && length > best_length
            best_start = index
            best_length = length
          end
          index = finish
        end

        return hextets.map { |value| value.to_s(16) }.join(":") unless best_start

        left = hextets[0...best_start].map { |value| value.to_s(16) }.join(":")
        right = hextets[(best_start + best_length)..].map { |value| value.to_s(16) }.join(":")
        return "::" if left.empty? && right.empty?
        return "::#{right}" if left.empty?
        return "#{left}::" if right.empty?

        "#{left}::#{right}"
      end

      def prefix_tokens(value, id, row_number)
        field = owned_string(value, "#{id}: row #{row_number} has no prefix field")
        field.split(",", -1).map do |piece|
          token = piece.strip
          token = token.sub(/\s+\[\d+\]\z/, "").rstrip while token.match?(/\s+\[\d+\]\z/)
          if token.empty? || token.include?("[") || token.include?("]")
            raise Error, "#{id}: row #{row_number} has an unsupported prefix annotation"
          end
          token
        end
      end
      private_class_method :prefix_tokens

      def owned_string(value, message)
        raise Error, message unless String === value

        text = String.new(value)
        raise Error, message unless text.valid_encoding?

        text
      end
      private_class_method :owned_string

      def digest_string(value, message)
        text = owned_string(value, message)
        raise Error, message unless text.match?(/\A[0-9a-f]{64}\z/)

        text
      end
      private_class_method :digest_string

      def utf8_string(value, message)
        raise Error, message unless String === value

        text = String.new(value)
        text.force_encoding(Encoding::UTF_8) if text.encoding == Encoding::ASCII_8BIT
        raise Error, message unless text.encoding == Encoding::UTF_8 && text.valid_encoding?

        text
      end
      private_class_method :utf8_string

      def parse_registry_metadata_xml(text, id, expected_registry_id)
        index = 0
        stack = []
        root_seen = false
        root_closed = false
        updated = []
        updated_text = nil

        while index < text.bytesize
          if text.getbyte(index) != 0x3c
            finish = text.index("<", index) || text.bytesize
            content = text.byteslice(index, finish - index)
            if stack.empty?
              raise Error, "#{id}: malformed registry metadata XML" unless content.match?(/\A[\t\n\r ]*\z/)
            elsif updated_text
              updated_text << content
            end
            index = finish
            next
          end

          if xml_token_at?(text, index, "<!--")
            raise Error, "#{id}: invalid registry update date" if updated_text

            finish = text.index("-->", index + 4)
            raise Error, "#{id}: malformed registry metadata XML" unless finish

            index = finish + 3
          elsif xml_token_at?(text, index, "<?")
            raise Error, "#{id}: invalid registry update date" if updated_text

            finish = text.index("?>", index + 2)
            raise Error, "#{id}: malformed registry metadata XML" unless finish

            index = finish + 2
          elsif xml_token_at?(text, index, "<![CDATA[")
            raise Error, "#{id}: malformed registry metadata XML" if stack.empty? || updated_text

            finish = text.index("]]>", index + 9)
            raise Error, "#{id}: malformed registry metadata XML" unless finish

            index = finish + 3
          elsif xml_token_at?(text, index, "<!")
            raise Error, "#{id}: metadata declarations are forbidden"
          elsif xml_token_at?(text, index, "</")
            finish = find_xml_tag_end(text, index + 2, id)
            name = parse_xml_end_tag(text.byteslice(index + 2, finish - index - 2), id)
            raise Error, "#{id}: malformed registry metadata XML" unless stack.last == name

            if updated_text && stack.length == 2 && name == "updated"
              updated << updated_text.freeze
              updated_text = nil
            end
            stack.pop
            root_closed = true if stack.empty?
            index = finish + 1
          else
            finish = find_xml_tag_end(text, index + 1, id)
            raw = text.byteslice(index + 1, finish - index - 1)
            name, attributes, self_closing = parse_xml_start_tag(raw, id)
            if stack.empty?
              raise Error, "#{id}: malformed registry metadata XML" if root_seen || root_closed
              unless name == "registry" && attributes["xmlns"] == IANA_XML_NAMESPACE
                raise Error, "#{id}: invalid registry metadata root"
              end
              if expected_registry_id && attributes["id"] != expected_registry_id
                raise Error, "#{id}: registry metadata identity differs"
              end
              root_seen = true
            elsif updated_text
              raise Error, "#{id}: invalid registry update date"
            elsif stack.length == 1 && name == "updated"
              updated_text = +""
            end

            if self_closing
              if updated_text && stack.length == 1 && name == "updated"
                updated << updated_text.freeze
                updated_text = nil
              end
              root_closed = true if stack.empty?
            else
              stack << name
            end
            index = finish + 1
          end
        end

        unless root_seen && root_closed && stack.empty? && updated_text.nil?
          raise Error, "#{id}: malformed registry metadata XML"
        end

        updated.freeze
      end
      private_class_method :parse_registry_metadata_xml

      def xml_token_at?(text, index, token)
        text.byteslice(index, token.bytesize) == token
      end
      private_class_method :xml_token_at?

      def find_xml_tag_end(text, index, id)
        quote = nil
        while index < text.bytesize
          byte = text.getbyte(index)
          if quote
            quote = nil if byte == quote
          elsif byte == 0x22 || byte == 0x27
            quote = byte
          elsif byte == 0x3e
            return index
          end
          index += 1
        end
        raise Error, "#{id}: malformed registry metadata XML"
      end
      private_class_method :find_xml_tag_end

      def parse_xml_end_tag(raw, id)
        match = /\A[\t\n\r ]*([A-Za-z_:][A-Za-z0-9_.:-]*)[\t\n\r ]*\z/.match(raw)
        raise Error, "#{id}: malformed registry metadata XML" unless match

        match[1]
      end
      private_class_method :parse_xml_end_tag

      def parse_xml_start_tag(raw, id)
        text = String.new(raw)
        self_closing = false
        trimmed = text.rstrip
        if trimmed.end_with?("/")
          self_closing = true
          trimmed = trimmed.delete_suffix("/").rstrip
        end

        name_match = /\A([A-Za-z_:][A-Za-z0-9_.:-]*)/.match(trimmed)
        raise Error, "#{id}: malformed registry metadata XML" unless name_match

        name = name_match[1]
        attributes = {}
        index = name_match.end(0)
        while index < trimmed.bytesize
          whitespace_start = index
          index += 1 while xml_whitespace_byte?(trimmed.getbyte(index))
          raise Error, "#{id}: malformed registry metadata XML" if index == whitespace_start

          attribute_match = /\A([A-Za-z_:][A-Za-z0-9_.:-]*)/.match(trimmed.byteslice(index..))
          raise Error, "#{id}: malformed registry metadata XML" unless attribute_match

          attribute = attribute_match[1]
          raise Error, "#{id}: duplicate XML attribute" if attributes.key?(attribute)

          index += attribute_match.end(0)
          index += 1 while xml_whitespace_byte?(trimmed.getbyte(index))
          raise Error, "#{id}: malformed registry metadata XML" unless trimmed.getbyte(index) == 0x3d

          index += 1
          index += 1 while xml_whitespace_byte?(trimmed.getbyte(index))
          quote = trimmed.getbyte(index)
          raise Error, "#{id}: malformed registry metadata XML" unless quote == 0x22 || quote == 0x27

          value_start = index + 1
          value_finish = trimmed.index(quote.chr, value_start)
          raise Error, "#{id}: malformed registry metadata XML" unless value_finish

          value = trimmed.byteslice(value_start, value_finish - value_start)
          raise Error, "#{id}: malformed registry metadata XML" if value.include?("<")

          attributes[attribute] = value.freeze
          index = value_finish + 1
        end

        [ name.freeze, attributes.freeze, self_closing ].freeze
      end
      private_class_method :parse_xml_start_tag

      def xml_whitespace_byte?(byte)
        byte == 0x20 || byte == 0x09 || byte == 0x0a || byte == 0x0d
      end
      private_class_method :xml_whitespace_byte?

      def reject_duplicate_json_keys!(text, id)
        index = scan_json_value(text, skip_json_whitespace(text, 0), id)
        index = skip_json_whitespace(text, index)
        raise Error, "#{id}: malformed snapshot JSON" unless index == text.bytesize
      end
      private_class_method :reject_duplicate_json_keys!

      def scan_json_value(text, index, id)
        case text.getbyte(index)
        when 0x7b # {
          scan_json_object(text, index, id)
        when 0x5b # [
          scan_json_array(text, index, id)
        when 0x22 # "
          scan_json_string(text, index).last
        else
          index += 1 while (byte = text.getbyte(index)) &&
            !json_whitespace_byte?(byte) && byte != 0x2c && byte != 0x5d && byte != 0x7d
          index
        end
      end
      private_class_method :scan_json_value

      def scan_json_object(text, index, id)
        keys = {}
        index = skip_json_whitespace(text, index + 1)
        return index + 1 if text.getbyte(index) == 0x7d

        loop do
          raise Error, "#{id}: malformed snapshot JSON" unless text.getbyte(index) == 0x22

          key, index = scan_json_string(text, index)
          raise Error, "#{id}: duplicate JSON object field" if keys.key?(key)

          keys[key] = true
          index = skip_json_whitespace(text, index)
          raise Error, "#{id}: malformed snapshot JSON" unless text.getbyte(index) == 0x3a

          index = scan_json_value(text, skip_json_whitespace(text, index + 1), id)
          index = skip_json_whitespace(text, index)
          case text.getbyte(index)
          when 0x2c
            index = skip_json_whitespace(text, index + 1)
          when 0x7d
            return index + 1
          else
            raise Error, "#{id}: malformed snapshot JSON"
          end
        end
      end
      private_class_method :scan_json_object

      def scan_json_array(text, index, id)
        index = skip_json_whitespace(text, index + 1)
        return index + 1 if text.getbyte(index) == 0x5d

        loop do
          index = scan_json_value(text, index, id)
          index = skip_json_whitespace(text, index)
          case text.getbyte(index)
          when 0x2c
            index = skip_json_whitespace(text, index + 1)
          when 0x5d
            return index + 1
          else
            raise Error, "#{id}: malformed snapshot JSON"
          end
        end
      end
      private_class_method :scan_json_array

      def scan_json_string(text, index)
        start = index
        index += 1
        loop do
          case text.getbyte(index)
          when 0x22
            token = text.byteslice(start, index - start + 1)
            return [ JSON.parse(token), index + 1 ]
          when 0x5c
            index += 2
          else
            index += 1
          end
        end
      end
      private_class_method :scan_json_string

      def skip_json_whitespace(text, index)
        index += 1 while json_whitespace_byte?(text.getbyte(index))
        index
      end
      private_class_method :skip_json_whitespace

      def json_whitespace_byte?(byte)
        byte == 0x20 || byte == 0x09 || byte == 0x0a || byte == 0x0d
      end
      private_class_method :json_whitespace_byte?

      def valid_iso_date?(value)
        match = /\A(\d{4})-(\d{2})-(\d{2})\z/.match(value)
        return false unless match

        year = Integer(match[1], 10)
        month = Integer(match[2], 10)
        day = Integer(match[3], 10)
        return false if year.zero? || !(1..12).cover?(month)

        leap_year = (year % 4).zero? && (!(year % 100).zero? || (year % 400).zero?)
        days = [ 31, leap_year ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 ]
        (1..days.fetch(month - 1)).cover?(day)
      end
      private_class_method :valid_iso_date?
    end
  end
end

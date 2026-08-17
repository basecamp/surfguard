# frozen_string_literal: true

require_relative "iana/generator"

module Surfguard
  module Iana
    module GeneratorCLI
      module_function

      def run_if_main(program_name, file_name, argv)
        return unless program_name == file_name

        exit run(argv)
      end

      def run(argv, out: $stdout, err: $stderr)
        case argv
        when [ "--check" ]
          Generator.check!
          out.puts "IANA generated constants: ok"
          0
        when [ "--update" ]
          changed = Generator.update!
          if changed
            out.puts "Updated generated IANA constants; review the diff"
          else
            out.puts "IANA generated constants already current"
          end
          0
        else
          err.puts "usage: script/generate_iana_data.rb --check|--update"
          2
        end
      end
    end
  end
end

Surfguard::Iana::GeneratorCLI.run_if_main($PROGRAM_NAME, __FILE__, ARGV)

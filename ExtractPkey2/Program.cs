using Mono.Options;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace ExtractPkey
{
    class Program
    {
        enum Mode
        {
            Private, Certificate
        }

        private static OptionSet options;

        static void Main(string[] args)
        {
            string folder = null, name = null, pin = null;
            Mode mode = Mode.Private;
            bool showHelp = false;

            options = new OptionSet {
                { "f|folder=",  "Путь к контейнеру", f => folder = f },
                { "r|reg=",  "Имя контейнера в реестре", r => name = r },
                { "private", "Извлечь закрытый ключ (по умолчанию)", p => { if (p != null) mode = Mode.Private; } },
                { "cert", "Извлечь сертификат", c => { if (c != null) mode = Mode.Certificate; } },
                { "p|pin=", "ПИН-код", p => pin = p },
                { "h|help", "Помощь", h => showHelp = h != null}
            };

            try {
                options.Parse(args);
            } catch (OptionException e) {
                Console.Error.WriteLine(e.Message);
                return;
            }

            if (showHelp) {
                PrintHelp();
                return;
            }

            Container container = null;
            if (!String.IsNullOrEmpty(folder)) {
                container = new FolderContainer(folder, pin);
            } else if (!String.IsNullOrEmpty(name)) {
                container = new RegistryContainer(name, pin);
            }

            if (container == null) {
                PrintHelp();
                return;
            }

            IExport export;
            if (mode == Mode.Certificate) {
                export = new CertificateExport();
            } else {
                export = new PrivateKeyExport();
            }

            try {
                export.Export(container, Console.OpenStandardOutput());
            } catch (Exception e) {
                Console.Error.WriteLine(e.Message);
            }
        }

        static void PrintHelp()
        {
            Console.WriteLine("Использование: extractpkey {ПАРАМЕТРЫ}");
            Console.WriteLine("Извлечение данных из контейнера Крипто ПРО");
            Console.WriteLine();
            Console.WriteLine("Параметры:");
            options.WriteOptionDescriptions(Console.Out);
        }
    }
}

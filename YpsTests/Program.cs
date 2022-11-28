using System.Collections.Generic;
using Consola;

namespace Yps
{ namespace Tests
{
    class Program
    {
        static int Main( string[] args ) {
                StdStream.Init(
                CreationFlags.TryConsole |
                CreationFlags.NoInputLog |
                CreationFlags.CreateLog
            );
            return test( new List<string>( args ) );
        }
        static int test( List<string> args ) {
            return new CrypsTests(
                 args.Contains("--verbose") 
                     || args.Contains("-v"),
                 args.Contains("--xmllogs")
                     || args.Contains("-x"),
                 args.Contains("--timelog")
                     || args.Contains("-t")
            ).Run().getFailures();
        }
    }
}
}

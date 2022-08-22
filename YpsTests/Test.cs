// Test.cs
/////////////////////////////////

using Consola;
using Consola.Test;
using System.Collections.Generic;
using Yps;

List<string> Args = new( args );

if( Args.Contains("-h")
 || Args.Contains("/?")
 || Args.Contains("--help") )
{
    StdStream.Init( CreationFlags.TryConsole );
    ILocked stream = StdStream.Out.Stream;
    stream.Put("\nTest result options:\n    ")
        .Put("--verbose, -v    -    generate ")
        .Put("more detailed result log which ")
        .Put("also contains PASS results\n    ")
        .Put("--xml, -x        -    generate ")
        .Put("test results as an xml document")
    .Put("\n").End();
    return 0;
}

/////////////////////////////////

StdStream.Init(
    CreationFlags.TryConsole |
    CreationFlags.NoInputLog |
    CreationFlags.CreateLog
);

Test test = new CrypsTests(
    Args.Contains("-v") ||
    Args.Contains("--verbose"),
    Args.Contains("--xml") ||
    Args.Contains("-x")
).Run();

return test.wasErrors() ? -1
     : test.hasPassed() ?  0
     : test.getFailures();

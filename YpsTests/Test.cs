// Test.cs
/////////////////////////////////

using Consola;
using Consola.Tests;
using System.Collections.Generic;
using Yps;

List<string> Args = new( args );

/////////////////////////////////

StdStream.Init(
    CreationFlags.TryConsole |
    CreationFlags.NoInputLog |
    CreationFlags.CreateLog
);

TestSuite test = new CrypsTests(
    Args.Contains("-v") ||
    Args.Contains("--verbose"),
    Args.Contains("--xml")
).Run();

return test.wasErrors() ?
  -1 : test.hasPassed() ?
   0 : test.getFailures();

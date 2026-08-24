namespace Demo.Dead;

public static class DeadCode
{
    public static void UnusedMethod()
    {
        System.Console.WriteLine("never called");
    }

    public const string UNUSED = "dead";
}

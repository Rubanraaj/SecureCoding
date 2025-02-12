using System;

class Program
{
    static void Main()
    {
        int x = int.MaxValue;
        int y = 1;
        int result;

        try
        {
            checked
            {
                result = x + y; 
            }
            Console.WriteLine("Result: " + result);
        }
        catch (OverflowException)
        {
            Console.WriteLine("Overflow occurred!");
        }
    }
}

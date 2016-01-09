using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Spring.Context;

namespace ConsoleApplication1
{
    public class A
    {
        public string Name { get; set; }
        public int Age { get; set; }
        public string GridType { get; set; }

        public A(string name, int age, string gridType)
        {
            this.Name = name;
            this.Age = age;
            this.GridType = gridType;
        }

        public override string ToString()
        {
            return $"{this.Name} - {this.Age} - {this.GridType}";
        }
    }

    public class B : A
    {
        public B(string name, int age, string gridType) : base(name, age, gridType)
        {
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            IApplicationContext context = Spring.Context.Support.ContextRegistry.GetContext();
            object test1 = context.GetObject("EQUITY_SWAP_EQUITY_RESET_VIEWMODEL");
            Console.WriteLine(test1.ToString());

            object test2 = context.GetObject("EQUITY_SWAP_INTEREST_RATE_RESET_VIEWMODEL");
            Console.WriteLine(test2.ToString());

        }
    }
}

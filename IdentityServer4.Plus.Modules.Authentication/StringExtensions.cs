namespace SSO
{
    public static class StringExtensions
    {
        public static string RemoveStartingZeroIfExists(this string number)
        {
            if (number?.StartsWith("0") == true)
            {
                number = number.Remove(0, 1);
            }

            return number;
        }
    }
}
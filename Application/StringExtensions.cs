//using ISmsBiz = Business.Interfaces.System.ISmsBiz;
using System.Collections.Generic;
using System.Globalization;

namespace SSO
{
    public static class StringExtensions
    {
        public static string ConvertEnglishChar(this string str)
        {
            if (string.IsNullOrWhiteSpace(str))
            {
                return str;
            }
            str = str.ConvertArabicToPersian();

            //char[] persianNumber = { '۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹' };
            //if (str.IndexOfAny(persianNumber) == 0) return str;

            var source = CultureInfo.GetCultureInfoByIetfLanguageTag("fa");
            var destination = CultureInfo.GetCultureInfoByIetfLanguageTag("en");

            for (int i = 0; i <= 9; i++)
            {
                str = str.Replace(source.NumberFormat.NativeDigits[i], destination.NumberFormat.NativeDigits[i]);
            }
            
            source = CultureInfo.GetCultureInfoByIetfLanguageTag("ar");

            for (int i = 0; i <= 9; i++)
            {
                str = str.Replace(source.NumberFormat.NativeDigits[i], destination.NumberFormat.NativeDigits[i]);
            }
            return str;
        }


        public static string ConvertArabicToPersian(this string str)
        {
            if (string.IsNullOrWhiteSpace(str))
            {
                return str;
            }

            Dictionary<string, string> charachters = new Dictionary<string, string>()
            {
                {"١" , "۱"},
                {"٢" , "۲"},
                {"٣" , "۳"},
                {"٤" , "۴"},
                {"٥" , "۵"},
                {"٦" , "۶"},
                {"٧" , "۷"},
                {"٨" , "۸"},
                {"٩" , "۹"},
                {"٠" , "۰"},
                {"ك" , "ک"},
                {"دِ" , "د"},
                {"بِ" , "ب"},
                {"زِ" , "ز"},
                {"ذِ" , "ذ"},
                {"شِ" , "ش"},
                {"سِ",  "س"},
                {"ى" , "ی"},
                {"ي" , "ی"},
            };

            foreach (KeyValuePair<string, string> value in charachters)
            {
                str.Replace(value.Key, value.Value);
            }

            return str;

        }

        public static string ToPersianNumber(this string input)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                return input;
            }

            string[] persian = new string[10] { "۰", "۱", "۲", "۳", "۴", "۵", "۶", "۷", "۸", "۹" };

            for (int j = 0; j < persian.Length; j++)
                input = input.Replace(persian[j], j.ToString());

            return input;
        }

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
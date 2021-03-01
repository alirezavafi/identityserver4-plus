namespace CoreLib.Services.Otp
{
    public sealed class SecurityToken
	{
		private readonly byte[] _data;

		public SecurityToken(byte[] data)
		{
			_data = (byte[])data.Clone();
		}

		internal byte[] GetDataNoClone()
		{
			return _data;
		}
	}
}
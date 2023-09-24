using Microsoft.AspNetCore.Identity;
using Isopoh.Cryptography.Argon2;
using Isopoh.Cryptography.SecureArray;
using System.Security.Cryptography;

namespace EvaluacionAlonsoSalazar.Helpers
{
    public static class Argon2PasswordHasher
    {
        public static string HashPassword(string password)
        {
            // Configure Argon2 with specific parameters
            var config = new Argon2Config
            {
                Type = Argon2Type.DataIndependentAddressing,
                Version = Argon2Version.Nineteen,
                TimeCost = 2, //Iterations
                MemoryCost = 65536,
                Lanes = 4, //Parallelism Factor
                Password = System.Text.Encoding.UTF8.GetBytes(password),
                Salt = RandomNumberGenerator.GetBytes(16),
                HashLength = 20
                //HashType = Argon2id
            };
            var argon2A = new Argon2(config);
            using (SecureArray<byte> hashA = argon2A.Hash())
            {
                return config.EncodeString(hashA.Buffer);

            }

        }

        public static bool VerifyHashedPassword(string hashedPassword, string password)
        {
            return Argon2.Verify(hashedPassword, password);
        }
    }
}

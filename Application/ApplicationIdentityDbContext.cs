using Microsoft.EntityFrameworkCore;
using System.Linq;

namespace SSO.Identity.Stores.EntityFramework
{
    public class ApplicationIdentityDbContext : DbContext
    {
        public ApplicationIdentityDbContext(DbContextOptions<ApplicationIdentityDbContext> options) : base(options)
        {
        }

        public DbSet<ApplicationUser> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.HasDefaultSchema("Identity");
            builder.Entity<ApplicationUser>(b =>
            {
                b.ToTable("Users");
                b.HasKey(u => u.Id);

                b.HasIndex(u => u.NormalizedUserName).HasName("NormalizedUserNameIndex").IsUnique();
                b.HasIndex(u => u.NationalCode).HasName("NationalCodeIndex").IsUnique();
                b.HasIndex(u => u.MobileNumber).HasName("MobileNumberIndex");
                b.HasIndex(u => u.Email).HasName("EmailIndex");

                // A concurrency token for use with the optimistic concurrency checking
                //b.Property(u => u.ConcurrencyStamp).IsConcurrencyToken();

                b.Property(u => u.UserName).HasMaxLength(20).IsRequired().IsUnicode(false);
                b.Property(u => u.NormalizedUserName).HasMaxLength(20).IsRequired().IsUnicode(false);
                b.Property(u => u.NationalCode).HasMaxLength(10).IsRequired().IsUnicode(false);
                b.Property(u => u.Email).HasMaxLength(100).IsUnicode(false);
                b.Property(u => u.PasswordHash).HasMaxLength(1024).IsUnicode(false);
                b.Property(u => u.MobileNumber).HasMaxLength(20).IsRequired().IsUnicode(false);
                b.Property(u => u.SecurityStamp).HasMaxLength(100).IsRequired().IsUnicode(false);
                b.Property(u => u.AuthenticationType).HasMaxLength(100).IsUnicode(false);
                b.Property(u => u.FirstName).IsUnicode().HasMaxLength(100).IsRequired();
                b.Property(u => u.LastName).IsUnicode().HasMaxLength(100).IsRequired();
            });
        }
    }
}

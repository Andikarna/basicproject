using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace AdidataDbContext.Models.Mysql.PTPDev
{
    public partial class PTPDevContext : DbContext
    {
        public PTPDevContext()
        {
        }

        public PTPDevContext(DbContextOptions<PTPDevContext> options)
            : base(options)
        {
        }

        public virtual DbSet<User> Users { get; set; } = null!;
        public virtual DbSet<UsersToken> UsersTokens { get; set; } = null!;

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            if (!optionsBuilder.IsConfigured)
            {
#warning To protect potentially sensitive information in your connection string, you should move it out of source code. You can avoid scaffolding the connection string by using the Name= syntax to read it from configuration - see https://go.microsoft.com/fwlink/?linkid=2131148. For more guidance on storing connection strings, see http://go.microsoft.com/fwlink/?LinkId=723263.
                optionsBuilder.UseMySql("server=localhost;port=3306;user=root;password=123456;database=PTP-Dev", Microsoft.EntityFrameworkCore.ServerVersion.Parse("8.0.28-mysql"));
            }
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.UseCollation("utf8mb4_0900_ai_ci")
                .HasCharSet("utf8mb4");

            modelBuilder.Entity<User>(entity =>
            {
                entity.ToTable("users");

                entity.Property(e => e.Id).HasColumnName("id");

                entity.Property(e => e.CreatedDate)
                    .HasColumnType("datetime")
                    .HasColumnName("created_date");

                entity.Property(e => e.Email)
                    .HasMaxLength(100)
                    .HasColumnName("email");

                entity.Property(e => e.Name)
                    .HasMaxLength(100)
                    .HasColumnName("name");

                entity.Property(e => e.Password)
                    .HasMaxLength(100)
                    .HasColumnName("password");

                entity.Property(e => e.Roleid).HasColumnName("roleid");

                entity.Property(e => e.UpdateDate)
                    .HasColumnType("datetime")
                    .HasColumnName("update_date");
            });

            modelBuilder.Entity<UsersToken>(entity =>
            {
                entity.ToTable("users_token");

                entity.Property(e => e.Id).HasColumnName("id");

                entity.Property(e => e.CreatedTime)
                    .HasColumnType("datetime")
                    .HasColumnName("created_time");

                entity.Property(e => e.ExpiredTime)
                    .HasColumnType("datetime")
                    .HasColumnName("expired_time");

                entity.Property(e => e.Hostname)
                    .HasMaxLength(100)
                    .HasColumnName("hostname");

                entity.Property(e => e.IpAddress)
                    .HasMaxLength(100)
                    .HasColumnName("ip_address");

                entity.Property(e => e.Nama)
                    .HasMaxLength(100)
                    .HasColumnName("nama");

                entity.Property(e => e.Token)
                    .HasColumnType("text")
                    .HasColumnName("token");

                entity.Property(e => e.UserId).HasColumnName("userId");
            });

            OnModelCreatingPartial(modelBuilder);
        }

        partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
    }
}

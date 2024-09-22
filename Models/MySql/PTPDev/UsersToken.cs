using System;
using System.Collections.Generic;

namespace AdidataDbContext.Models.Mysql.PTPDev
{
    public partial class UsersToken
    {
        public int Id { get; set; }
        public string? Nama { get; set; }
        public string? Token { get; set; }
        public DateTime? CreatedTime { get; set; }
        public DateTime? ExpiredTime { get; set; }
        public string? IpAddress { get; set; }
        public string? Hostname { get; set; }
        public int? UserId { get; set; }
    }
}

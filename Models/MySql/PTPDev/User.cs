using System;
using System.Collections.Generic;

namespace AdidataDbContext.Models.Mysql.PTPDev
{
    public partial class User
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public string? Email { get; set; }
        public string? Password { get; set; }
        public int? Roleid { get; set; }
        public DateTime? CreatedDate { get; set; }
        public DateTime? UpdateDate { get; set; }
    }
}

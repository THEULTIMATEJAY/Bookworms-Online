﻿using System.ComponentModel.DataAnnotations;
namespace Bookworms_Online.Models
{
    public class LoginViewModel
    {
        [Required, EmailAddress]
        public string Email { get; set; }

        [Required, DataType(DataType.Password)]
        public string Password { get; set; }

        public string? ReturnUrl { get; set; }

        public bool RememberMe { get; set; }


        public string ReCaptchaToken { get; set; }
    }
}

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using ManualApp.Models;
using System.ComponentModel.DataAnnotations;
using System.Text;

namespace ManualApp.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<ResetPasswordModel> _logger;

        public ResetPasswordModel(UserManager<ApplicationUser> userManager, ILogger<ResetPasswordModel> logger)
        {
            _userManager = userManager;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public class InputModel
        {
            public string Email { get; set; }

            [Required(ErrorMessage = "パスワードは必須です")]
            [StringLength(100, ErrorMessage = "パスワードは{2}文字以上{1}文字以内で入力してください", MinimumLength = 8)]
            [DataType(DataType.Password)]
            [Display(Name = "新しいパスワード")]
            public string Password { get; set; }

            [DataType(DataType.Password)]
            [Display(Name = "パスワード確認")]
            [Compare("Password", ErrorMessage = "パスワードと確認パスワードが一致しません")]
            public string ConfirmPassword { get; set; }

            public string Code { get; set; }
        }

        public IActionResult OnGet(string code = null, string email = null)
        {
            if (code == null || email == null)
            {
                return BadRequest("リセットコードとメールアドレスが必要です。");
            }
            else
            {
                Input = new InputModel
                {
                    Code = code,
                    Email = email
                };
                return Page();
            }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                // ユーザーが存在しない場合でも成功メッセージを表示（セキュリティのため）
                _logger.LogWarning("パスワードリセット試行: 存在しないユーザー - {Email}", Input.Email);
                return RedirectToPage("./ResetPasswordConfirmation");
            }

            // トークンをデコード
            var code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(Input.Code));
            
            var result = await _userManager.ResetPasswordAsync(user, code, Input.Password);
            if (result.Succeeded)
            {
                _logger.LogInformation("パスワードリセットが成功しました: {Email}", Input.Email);
                return RedirectToPage("./ResetPasswordConfirmation");
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
            return Page();
        }
    }
}

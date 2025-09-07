using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ManualApp.Models;
using System.ComponentModel.DataAnnotations;

namespace ManualApp.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly ILogger<ForgotPasswordModel> _logger;

        public ForgotPasswordModel(UserManager<ApplicationUser> userManager, IEmailSender emailSender, ILogger<ForgotPasswordModel> logger)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "メールアドレスは必須です")]
            [EmailAddress(ErrorMessage = "有効なメールアドレスを入力してください")]
            [Display(Name = "メールアドレス")]
            public string Email { get; set; }
        }

        public IActionResult OnGet()
        {
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(Input.Email);
                if (user == null)
                {
                    // ユーザーが存在しない場合
                    _logger.LogWarning("パスワードリセット要求: 存在しないユーザー - {Email}", Input.Email);
                    ModelState.AddModelError(string.Empty, "指定されたメールアドレスのユーザーが見つかりません。");
                    return Page();
                }
                
                if (!(await _userManager.IsEmailConfirmedAsync(user)))
                {
                    // メール未確認の場合
                    _logger.LogWarning("パスワードリセット要求: メール未確認ユーザー - {Email}", Input.Email);
                    ModelState.AddModelError(string.Empty, "メールアドレスが確認されていません。確認メールをチェックして、メールアドレスを確認してから再度お試しください。");
                    return Page();
                }

                // パスワードリセットトークンを生成
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                code = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(System.Text.Encoding.UTF8.GetBytes(code));
                var callbackUrl = Url.Page(
                    "/Account/ResetPassword",
                    pageHandler: null,
                    values: new { area = "Identity", code = code, email = Input.Email },
                    protocol: Request.Scheme);

                await _emailSender.SendEmailAsync(Input.Email, "パスワードリセット",
                    $"パスワードをリセットするには、<a href='{callbackUrl}'>こちらをクリック</a>してください。");

                _logger.LogInformation("パスワードリセットメールを送信しました: {Email}", Input.Email);
                return RedirectToPage("./ForgotPasswordConfirmation");
            }

            return Page();
        }
    }
}

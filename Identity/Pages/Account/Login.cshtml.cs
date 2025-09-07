using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using ManualApp.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ManualApp.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, ILogger<LoginModel> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "メールアドレスは必須です")]
            [EmailAddress(ErrorMessage = "有効なメールアドレスを入力してください")]
            [Display(Name = "メールアドレス")]
            public string Email { get; set; }

            [Required(ErrorMessage = "パスワードは必須です")]
            [DataType(DataType.Password)]
            [Display(Name = "パスワード")]
            public string Password { get; set; }

            [Display(Name = "ログイン状態を保持する")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl ??= Url.Content("~/");

            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (ModelState.IsValid)
            {
                // まずユーザーが存在するかチェック
                var user = await _userManager.FindByEmailAsync(Input.Email);
                if (user != null && !user.EmailConfirmed)
                {
                    ModelState.AddModelError(string.Empty, "メールアドレスの認証がされていません。送信されたメールに記載のURLをクリックして認証を行ってください。");
                    return Page();
                }

                // メール確認を必須にするため、PasswordSignInAsyncの第4引数をtrueに設定
                var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    // ログイン成功後も再度メール確認状態をチェック
                    var currentUser = await _userManager.FindByEmailAsync(Input.Email);
                    if (currentUser != null && !currentUser.EmailConfirmed)
                    {
                        await _signInManager.SignOutAsync();
                        ModelState.AddModelError(string.Empty, "メールアドレスが確認されていません。確認メールをチェックしてください。");
                        return Page();
                    }
                    return LocalRedirect(returnUrl);
                }
                if (result.RequiresTwoFactor)
                {
                    return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    return RedirectToPage("./Lockout");
                }
                if (result.IsNotAllowed)
                {
                    // メール未確認の場合
                    ModelState.AddModelError(string.Empty, "メールアドレスが確認されていません。確認メールをチェックしてください。");
                    return Page();
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "ログインに失敗しました。メールアドレスとパスワードを確認してください。");
                    return Page();
                }
            }

            return Page();
        }
    }
}

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using ManualApp.Models;
using System.ComponentModel.DataAnnotations;
using System.Threading;

namespace ManualApp.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class ExternalLoginDisplayNameModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IUserStore<ApplicationUser> _userStore;
        private readonly IUserEmailStore<ApplicationUser> _emailStore;
        private readonly ILogger<ExternalLoginDisplayNameModel> _logger;
        private readonly IEmailSender _emailSender;

        public ExternalLoginDisplayNameModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            IUserStore<ApplicationUser> userStore,
            ILogger<ExternalLoginDisplayNameModel> logger,
            IEmailSender emailSender)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _userStore = userStore;
            _emailStore = GetEmailStore();
            _logger = logger;
            _emailSender = emailSender;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public class InputModel
        {
            [Required(ErrorMessage = "表示名は必須です")]
            [StringLength(50, ErrorMessage = "表示名は{1}文字以内で入力してください", MinimumLength = 1)]
            [Display(Name = "表示名")]
            public string DisplayName { get; set; }
        }

        public IActionResult OnGet(string returnUrl = null)
        {
            // 外部ログイン情報がTempDataに存在するかチェック
            if (!TempData.ContainsKey("ExternalLoginEmail"))
            {
                return Redirect("/Identity/Account/Login");
            }

            ReturnUrl = returnUrl;
            return Page();
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");

            // 外部ログイン情報がTempDataに存在するかチェック
            if (!TempData.ContainsKey("ExternalLoginEmail"))
            {
                return Redirect("/Identity/Account/Login");
            }

            if (ModelState.IsValid)
            {
                try
                {
                    // TempDataから外部ログイン情報を取得
                    var email = TempData["ExternalLoginEmail"]?.ToString();
                    var provider = TempData["ExternalLoginProvider"]?.ToString();
                    var providerKey = TempData["ExternalLoginProviderKey"]?.ToString();
                    var providerDisplayName = TempData["ExternalLoginProviderDisplayName"]?.ToString();

                    if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(provider) || string.IsNullOrEmpty(providerKey))
                    {
                        ErrorMessage = "外部ログイン情報が無効です。";
                        return Redirect("/Identity/Account/Login");
                    }

                    // 新しいユーザーを作成
                    var user = CreateUser();
                    await _userStore.SetUserNameAsync(user, email, CancellationToken.None);
                    await _emailStore.SetEmailAsync(user, email, CancellationToken.None);
                    user.DisplayName = Input.DisplayName;
                    user.EmailConfirmed = true; // Googleログインの場合はメール認証済みとする

                    // ユーザーを作成
                    var createResult = await _userManager.CreateAsync(user);
                    if (createResult.Succeeded)
                    {
                        // 外部ログイン情報を再構築
                        var externalLoginInfo = new Microsoft.AspNetCore.Identity.ExternalLoginInfo(
                            new System.Security.Claims.ClaimsPrincipal(),
                            provider,
                            providerKey,
                            providerDisplayName);

                        // 外部ログイン情報を追加
                        var addLoginResult = await _userManager.AddLoginAsync(user, externalLoginInfo);
                        if (addLoginResult.Succeeded)
                        {
                            // Googleログインの場合はメール認証をスキップして即座にログイン
                            await _signInManager.SignInAsync(user, isPersistent: false, provider);
                            return Redirect(returnUrl);
                        }
                        else
                        {
                            // 外部ログイン追加に失敗した場合、ユーザーを削除
                            await _userManager.DeleteAsync(user);
                            ErrorMessage = "外部ログイン情報の追加に失敗しました。";
                        }
                    }
                    else
                    {
                        foreach (var error in createResult.Errors)
                        {
                            ModelState.AddModelError(string.Empty, error.Description);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "外部ログインでのユーザー作成中にエラーが発生しました");
                    ErrorMessage = "ユーザー作成中にエラーが発生しました。";
                }
            }

            ReturnUrl = returnUrl;
            return Page();
        }

        private ApplicationUser CreateUser()
        {
            try
            {
                return Activator.CreateInstance<ApplicationUser>();
            }
            catch
            {
                throw new InvalidOperationException($"Can't create an instance of '{nameof(ApplicationUser)}'. " +
                    $"Ensure that '{nameof(ApplicationUser)}' is not an abstract class and has a parameterless constructor, or alternatively " +
                    $"override the external login page in /Areas/Identity/Pages/Account/ExternalLoginDisplayName.cshtml");
            }
        }

        private IUserEmailStore<ApplicationUser> GetEmailStore()
        {
            if (!_userManager.SupportsUserEmail)
            {
                throw new NotSupportedException("The default UI requires a user store with email support.");
            }
            return (IUserEmailStore<ApplicationUser>)_userStore;
        }
    }
}

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using ManualApp.Models;
using System.Text;
using System.Linq;

namespace ManualApp.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class ConfirmEmailModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<ConfirmEmailModel> _logger;

        public ConfirmEmailModel(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, ILogger<ConfirmEmailModel> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [TempData]
        public string StatusMessage { get; set; }

        public async Task<IActionResult> OnGetAsync(string userId, string code, string data, string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");
            
            // 新しい登録フロー（dataパラメータがある場合）
            if (!string.IsNullOrEmpty(data))
            {
                try
                {
                    // 登録情報をデコード
                    var decodedData = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(data));
                    var registrationData = System.Text.Json.JsonSerializer.Deserialize<RegistrationData>(decodedData);
                    
                    if (registrationData == null || string.IsNullOrEmpty(registrationData.Email))
                    {
                        StatusMessage = "登録情報が無効です。";
                        return Page();
                    }
                    
                    // ユーザーが既に存在するかチェック
                    var existingUser = await _userManager.FindByEmailAsync(registrationData.Email);
                    if (existingUser != null)
                    {
                        StatusMessage = "このメールアドレスは既に登録されています。";
                        return Page();
                    }
                    
                    // 新しいユーザーを作成
                    var user = new ApplicationUser
                    {
                        UserName = registrationData.Email,
                        Email = registrationData.Email,
                        DisplayName = registrationData.DisplayName,
                        EmailConfirmed = true // メール認証済みとして作成
                    };
                    
                    var createResult = await _userManager.CreateAsync(user, registrationData.Password);
                    if (createResult.Succeeded)
                    {
                        StatusMessage = "アカウントが作成され、メールアドレスが確認されました。";
                        
                        // 自動ログイン
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        
                        return Redirect(returnUrl);
                    }
                    else
                    {
                        StatusMessage = "アカウントの作成に失敗しました。";
                        foreach (var error in createResult.Errors)
                        {
                            StatusMessage += $" {error.Description}";
                        }
                        return Page();
                    }
                }
                catch (Exception ex)
                {
                    StatusMessage = "登録情報の処理中にエラーが発生しました。";
                    return Page();
                }
            }
            
            // 従来のメール認証フロー（userIdとcodeがある場合）
            if (userId == null || code == null)
            {
                return Redirect("/");
            }

            var user2 = await _userManager.FindByIdAsync(userId);
            if (user2 == null)
            {
                return NotFound($"ユーザーID '{userId}' のユーザーが見つかりません。");
            }

            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            var result = await _userManager.ConfirmEmailAsync(user2, code);
            
            if (result.Succeeded)
            {
                StatusMessage = "メールアドレスが確認されました。";
                
                // メール認証成功後に自動ログイン
                await _signInManager.SignInAsync(user2, isPersistent: false);
                
                return Redirect(returnUrl);
            }
            else
            {
                StatusMessage = "メールアドレスの確認に失敗しました。";
                return Page();
            }
        }
        
        public class RegistrationData
        {
            public string Email { get; set; } = string.Empty;
            public string DisplayName { get; set; } = string.Empty;
            public string Password { get; set; } = string.Empty;
        }
    }
}

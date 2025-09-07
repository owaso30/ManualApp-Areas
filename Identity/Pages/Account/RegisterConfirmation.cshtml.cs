using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ManualApp.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class RegisterConfirmationModel : PageModel
    {
        [BindProperty]
        public string Email { get; set; }

        [BindProperty]
        public string ReturnUrl { get; set; }

        public IActionResult OnGet(string email, string returnUrl = null)
        {
            if (email == null)
            {
                return Redirect("/");
            }

            Email = email;
            ReturnUrl = returnUrl;
            return Page();
        }
    }
}

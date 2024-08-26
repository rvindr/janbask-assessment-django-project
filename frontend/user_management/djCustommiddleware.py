from django.shortcuts import redirect
from django.utils.deprecation import MiddlewareMixin

class LoginRequiredMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # List of exact URLs that don't require login
        exempt_urls = [
            '/login/',
            '/register/',
            '/change-password/',
            '/admin/',
            '/reset-password/',  # Base reset-password URL
        ]

        path = request.path_info

        # Directly exempt the reset-password URL without regex for now
        if path.startswith('/reset-password/'):
            return None

        if not request.session.get('auth_token') and path not in exempt_urls:
            return redirect('login')

        return None

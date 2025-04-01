document.addEventListener("alpine:init", () => { Alpine.store("auth", {
      authFormVisible: true,
      menuButtonVisible: false,
      resetFormVisible: false,
      newPasswordVisible: false,
      showLoginForm() {
        this.authFormVisible = true;
        this.resetFormVisible = false;
        this.newPasswordVisible = false;
      },
      hideAuthForm() {
        this.authFormVisible = false;
        this.resetFormVisible = false;
        this.newPasswordVisible = false;
      },
      showResetForm() {
        this.authFormVisible = false;
        this.resetFormVisible = true;
        this.newPasswordVisible = false;
      },
      showNewPasswordForm() {
        this.authFormVisible = false;
        this.resetFormVisible = false;
        this.newPasswordVisible = true;
      },
      resetCodeSentMsg() {
        Swal.fire({
          toast: true,
          position: 'top-end',
          icon: 'success',
          title: 'Password reset code is sent to your email address, please verify the code.',
          showConfirmButton: false,
          timer: 2500
        })
      },
      resetFailedMsg() {
        Swal.fire({
          toast: true,
          position: 'top-end',
          icon: 'success',
          title: 'No such email address, please ensure that the email address you entered is correct.',
          showConfirmButton: false,
          timer: 2500
        })
      },
      async validSessionMsg() {
        Swal.fire({
          toast: true,
          position: 'top-end',
          icon: 'success',
          title: 'Session has been continued.',
          showConfirmButton: false,
          timer: 2500
        })
      },
      async loginSuccess() {
        Swal.fire({
          toast: true,
          position: 'top-end',
          icon: 'success',
          title: 'Login Success.',
          showConfirmButton: false,
          timer: 2500
        })
      },
      invalidTokenMsg() {
        Swal.fire({
          toast: true,
          position: 'top-end',
          icon: 'error',
          title: 'Session was ended, please login again.',
          showConfirmButton: false,
          timer: 2500
        })
      },
      invalidLoginMsg() {
        Swal.fire({
          toast: true,
          position: 'top-end',
          icon: 'error',
          title: 'Incorrect login credentials, Enter correct email and password.',
          showConfirmButton: false,
          timer: 2500
        })
      },
      async isLoggedIn() {
        const token = localStorage.getItem('token');
        if (!token) {
          this.showLoginForm();
          return false;
        }
        axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
        axios.defaults.headers.common['Content-Type'] = "application/json";
        try {
          await axios.get('/api/validify', {
            headers: { Authorization: `Bearer ${token}` },
            responseType: 'text'
          });
          this.hideAuthForm();
          this.validSessionMsg();
          return true;
        } catch {
          localStorage.removeItem('token');
          this.showLoginForm();
          this.invalidTokenMsg();
          return false;
        }
      },
      async login(email, password) {
        var payload = JSON.stringify({
          email: email,
          password: password,
        });
        try {
  
          let resp = (await axios.post('/api/login', payload)).data;
          localStorage.setItem('token', resp.token);
          axios.defaults.headers.common['Authorization'] = `Bearer ${resp.token}`;
          this.hideAuthForm();
          this.loginSuccess();
        } catch (error) {
          this.showLoginForm();
          this.invalidLoginMsg();
          console.log("Error: " + error);
        }
      },
  
      async register(email, password, name) {
        var payload = JSON.stringify({
          email: email,
          password: password,
          name: name,
        });
  
        try {
          await axios.post('/api/register', payload);
        } catch (error) {
          Swal.fire({
            toast: true,
            position: 'top-end',
            icon: 'error',
            title: 'Sending code failed. Please try again.',
            showConfirmButton: false,
            timer: 2500
          });
          console.log("Error: " + error);
        }
      },
      async activate(email, code) {
        var payload = JSON.stringify({
          email: email,
          verification: {code: code},
        });
  
        try {
          let data = (await axios.post('/api/register/activate', payload)).data;
          localStorage.setItem('token', data.token);
          axios.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
          Swal.fire({
            toast: true,
            position: 'top-end',
            icon: 'success',
            title: 'Registration successful.',
            showConfirmButton: false,
            timer: 2500
          });
          this.hideAuthForm();
          this.loginSuccess();
        } catch (error) {
          Swal.fire({
            toast: true,
            position: 'top-end',
            icon: 'error',
            title: 'Registration failed. Please try again.',
            showConfirmButton: false,
            timer: 2500
          });
          console.log("Error: " + error);
        }
      },
      logout() {
        localStorage.removeItem('token');
        delete axios.defaults.headers.common['Authorization'];
        this.showLoginForm();
        Swal.fire({
          toast: true,
          position: 'top-end',
          icon: 'success',
          title: 'Logged out successfully.',
          showConfirmButton: false,
          timer: 2500
        });
      },
    
      async sendResetPassword(email) {
        try {
          let data = JSON.stringify({ email });
          let response = await axios.post('/api/reset', data);
          
          if (response.status === 200) {
            await successToast("Reset password code sent successfully.");
          } else {
            throw new Error('Unexpected response status');
          }
        } catch (error) {
          console.error('Password reset request failed:', error);
          
          if (error.response && error.response.status === 404) {
            this.resetFailedMsg();
          } else {
            Swal.fire({
              toast: true,
              position: 'top-end',
              icon: 'error',
              title: 'An error occurred. Please try again later.',
              showConfirmButton: false,
              timer: 2500
            });
          }
        }
      }, 
      async resetPassword(email, code, password) {
        try {
          let data = JSON.stringify({ email, code, password });
          await axios.post('/api/reset/activate', data);
          Swal.fire({
            toast: true,
            position: 'top-end',
            icon:'success',
            title: 'Password reset successful.',
            showConfirmButton: false,
            timer: 2500
          });
          await this.login(email, password);
          this.hideAuthForm();
        } catch (error) {
          console.error('Password reset failed:', error);
          Swal.fire({
            toast: true,
            position: 'top-end',
            icon: 'error',
            title: 'An error occurred. Please try again later.',
            showConfirmButton: false,
            timer: 2500
          });
        }
      }
})})
  
  
  
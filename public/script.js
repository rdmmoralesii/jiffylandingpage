const SignUpForm = () => {
  const [formData, setFormData] = React.useState({
    companyName: '',
    companyAddress: '',
    branchCount: '',
    contactPerson: '',
    contactEmail: '',
    contactNumber: '',
  });
  const [submitted, setSubmitted] = React.useState(false);
  const [error, setError] = React.useState(null);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    setError(null);
    fetch('/api/signup', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(formData),
    })
    .then(response => {
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    })
    .then(data => {
      console.log('Success:', data);
      setFormData({
        companyName: '',
        companyAddress: '',
        branchCount: '',
        contactPerson: '',
        contactEmail: '',
        contactNumber: '',
      });
      setSubmitted(true);
    })
    .catch((error) => {
      console.error('Error:', error);
      setError('An error occurred. Please try again.');
    });
  };

  if (submitted) {
    return (
      <div className="success-message">
        <h2>Thank You!</h2>
        <p>Your information has been received. We will get back to you as soon as we can! Thank you very much!</p>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="sign-up-form">
      <h2>Sign Up</h2>
      {error && <p className="error-message">{error}</p>}
      <input
        type="text"
        name="companyName"
        value={formData.companyName}
        onChange={handleChange}
        placeholder="Company Name"
        required
      />
      <input
        type="text"
        name="companyAddress"
        value={formData.companyAddress}
        onChange={handleChange}
        placeholder="Company Main Address"
        required
      />
      <input
        type="number"
        name="branchCount"
        value={formData.branchCount}
        onChange={handleChange}
        placeholder="Number of Branches to Deploy"
        required
      />
      <input
        type="text"
        name="contactPerson"
        value={formData.contactPerson}
        onChange={handleChange}
        placeholder="Contact Person"
        required
      />
      <input
        type="email"
        name="contactEmail"
        value={formData.contactEmail}
        onChange={handleChange}
        placeholder="Contact Email"
        required
      />
      <input
        type="tel"
        name="contactNumber"
        value={formData.contactNumber}
        onChange={handleChange}
        placeholder="Contact Number"
        required
      />
      <button type="submit" className="btn">Submit</button>
    </form>
  );
};

const LandingPage = () => {
  const [showSignUpForm, setShowSignUpForm] = React.useState(false);

  return (
    <div className="flex flex-col min-h-screen">
      <header>
        <nav className="container">
          <div className="logo">Jiffy</div>
          <ul>
            <li><a href="#features">How It Works</a></li>
            <li><a href="#testimonials">Testimonials</a></li>
            <li><a href="#pricing">Pricing</a></li>
            <li><a href="#contact">Contact</a></li>
          </ul>
          <a href="#" className="btn" onClick={() => setShowSignUpForm(true)}>Sign Up Free</a>
        </nav>
      </header>
      <main>
        <section id="hero">
          <div className="container">
            <h1>Feedback, Grow & Take Action -- all in a Jiffy</h1>
            <p>Get real-time insights through NPS surveys and seamlessly manage them with integrated CRM.</p>
            <a href="#" className="btn" onClick={() => setShowSignUpForm(true)}>Free Sign Up Today</a>
          </div>
        </section>
        {showSignUpForm && (
          <div className="modal">
            <div className="modal-content">
              <span className="close" onClick={() => setShowSignUpForm(false)}>&times;</span>
              <SignUpForm />
            </div>
          </div>
        )}
        <section id="features">
          <div className="container">
            <h2>How It Works</h2>
            <div className="feature-grid">
              <div className="feature-item">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
                </svg>
                <h3>Mobile-Friendly NPS Surveys</h3>
                <p>Quickly gather customer feedback with intuitive, mobile-optimized NPS surveys.</p>
              </div>
              <div className="feature-item">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                </svg>
                <h3>Seamless CRM Integration</h3>
                <p>Effortlessly manage customer insights with our built-in CRM system.</p>
              </div>
              <div className="feature-item">
                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
                <h3>Actionable Insights</h3>
                <p>Turn raw data into clear, actionable strategies for your business.</p>
              </div>
            </div>
          </div>
        </section>
      </main>
      <footer>
        <div className="container">
          <div className="footer-content">
            <div className="footer-section">
              <h4>About Us</h4>
              <p>Jiffy helps restaurants improve customer satisfaction through easy-to-use surveys and powerful analytics.</p>
            </div>
            <div className="footer-section">
              <h4>Quick Links</h4>
              <ul>
                <li><a href="#features">Features</a></li>
                <li><a href="#testimonials">Testimonials</a></li>
                <li><a href="#pricing">Pricing</a></li>
                <li><a href="#contact">Contact</a></li>
              </ul>
            </div>
            <div className="footer-section">
              <h4>Contact Us</h4>
              <p>Email: info@jiffy.com</p>
              <p>Phone: (123) 456-7890</p>
            </div>
          </div>
          <div className="footer-bottom">
            <p>&copy; 2023 Jiffy. All rights reserved.</p>
          </div>
        </div>
        <button onClick={() => window.location.href = '/admin'} className="admin-login-btn">Admin Login</button>
      </footer>
    </div>
  );
};

ReactDOM.render(<LandingPage />, document.getElementById('root'));
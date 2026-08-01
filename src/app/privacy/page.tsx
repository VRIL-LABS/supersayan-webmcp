import Link from 'next/link';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Privacy Policy — SuperSayanMCP',
  description: 'Privacy Policy for SuperSayanMCP and VLABS, LLC.',
};

const EFFECTIVE_DATE = 'July 1, 2026';
const COMPANY = 'VLABS, LLC';
const PRODUCT = 'SuperSayanMCP';
const CONTACT_EMAIL = 'privacy@vril.li';
const SITE_URL = 'https://supersayan.vril.li';

export default function PrivacyPage() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Nav bar */}
      <div className="border-b border-white/10 flex items-center justify-between px-6 py-4 max-w-5xl mx-auto w-full">
        <Link href="/" className="text-sm text-white/60 hover:text-white transition-colors">
          &larr; Back to {PRODUCT}
        </Link>
        <a href="https://vril.li" target="_blank" rel="noopener noreferrer" aria-label="VRIL LABS">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/vril-labs-logo.svg" alt="VRIL LABS" className="h-6 w-auto opacity-70 hover:opacity-100 transition-opacity" />
        </a>
      </div>

      <main className="max-w-3xl mx-auto px-6 py-16">
        <h1 className="text-4xl font-bold mb-2 text-white">Privacy Policy</h1>
        <p className="text-white/50 text-sm mb-10">Effective Date: {EFFECTIVE_DATE} &mdash; Last Updated: {EFFECTIVE_DATE}</p>

        <Section title="1. Introduction">
          <p>
            {COMPANY} (&ldquo;Company,&rdquo; &ldquo;we,&rdquo; &ldquo;us,&rdquo; or &ldquo;our&rdquo;) operates {PRODUCT} (the &ldquo;Service&rdquo;)
            accessible at <a href={SITE_URL} className="text-[#00FFC8] hover:underline">{SITE_URL}</a>.
            This Privacy Policy describes how we collect, use, disclose, and safeguard your information when you visit or use our Service.
            By accessing the Service, you agree to the terms of this Privacy Policy.
          </p>
          <p className="mt-3">
            This Policy complies with the California Consumer Privacy Act of 2018 as amended by the California Privacy Rights Act of 2020
            (&ldquo;CCPA/CPRA&rdquo;), the Delaware Online and Personal Privacy Protection Act (&ldquo;DOPPA&rdquo;), and other applicable
            U.S. federal and state privacy laws.
          </p>
        </Section>

        <Section title="2. Information We Collect">
          <p className="mb-3">We may collect the following categories of information:</p>
          <ul className="list-disc list-inside space-y-2 text-white/70">
            <li><strong className="text-white">Browser &amp; Device Data:</strong> User agent string, browser type and version, operating system, screen resolution, installed plugins, hardware concurrency, and device memory — collected client-side for security analysis purposes only.</li>
            <li><strong className="text-white">Network Data:</strong> IP address, connection type, and inferred geolocation at the city/region level.</li>
            <li><strong className="text-white">Behavioral Signals:</strong> Mouse movement patterns, keystroke timing, and scroll behavior used solely to distinguish human users from automated agents. This data is processed locally in your browser and is not transmitted to our servers unless you explicitly initiate a scan report.</li>
            <li><strong className="text-white">Usage Data:</strong> Pages visited, features used, time spent, and referral source via standard server logs.</li>
            <li><strong className="text-white">Communications:</strong> If you contact us by email, we retain the content of that communication and your contact details.</li>
          </ul>
          <p className="mt-3">
            We do not intentionally collect sensitive personal information as defined by the CPRA (e.g., Social Security numbers, financial account numbers, precise geolocation, health data, or the contents of private communications).
          </p>
        </Section>

        <Section title="3. How We Use Your Information">
          <p className="mb-3">We use the information we collect for the following business purposes:</p>
          <ul className="list-disc list-inside space-y-2 text-white/70">
            <li>To provide, operate, and maintain the Service and its security detection features.</li>
            <li>To analyze and improve the accuracy of our WebMCP and AI agent detection algorithms.</li>
            <li>To monitor for abuse, fraud, unauthorized access, or malicious use of the Service.</li>
            <li>To respond to your inquiries and support requests.</li>
            <li>To comply with applicable law, legal process, or enforceable governmental requests.</li>
            <li>To enforce our Terms of Service and protect the rights, property, or safety of the Company and its users.</li>
          </ul>
          <p className="mt-3">
            We do not sell your personal information. We do not share your personal information with third parties for those third parties&apos; direct marketing purposes.
          </p>
        </Section>

        <Section title="4. Disclosure of Your Information">
          <p className="mb-3">We may disclose your information to the following categories of recipients:</p>
          <ul className="list-disc list-inside space-y-2 text-white/70">
            <li><strong className="text-white">Service Providers:</strong> Third-party vendors who perform services on our behalf (e.g., cloud hosting, analytics, email delivery) and are contractually bound to use your data only as directed by us.</li>
            <li><strong className="text-white">Legal Requirements:</strong> Where required by applicable law, court order, or governmental authority.</li>
            <li><strong className="text-white">Business Transfers:</strong> In connection with any merger, acquisition, reorganization, or sale of all or substantially all of our assets, your information may be transferred as a business asset. We will notify you before your personal information is transferred and becomes subject to a different privacy policy.</li>
            <li><strong className="text-white">Protection of Rights:</strong> To investigate, prevent, or take action regarding illegal activities, suspected fraud, threats to physical safety, or violations of our Terms of Service.</li>
          </ul>
        </Section>

        <Section title="5. Cookies and Tracking Technologies">
          <p>
            The Service may use session cookies and similar technologies to maintain session state and measure Service performance.
            We do not use third-party advertising cookies or cross-site tracking cookies.
            You may configure your browser to refuse cookies; however, certain features of the Service may not function properly as a result.
          </p>
        </Section>

        <Section title="6. Data Retention">
          <p>
            We retain personal information only for as long as necessary to fulfill the purposes described in this Policy, unless a longer
            retention period is required or permitted by law. Server log data is retained for no more than 90 days. Scan results processed
            locally in your browser are not stored on our servers and are discarded when you close or refresh the page.
          </p>
        </Section>

        <Section title="7. Security">
          <p>
            We implement commercially reasonable technical, administrative, and physical safeguards designed to protect your information
            from unauthorized access, disclosure, alteration, or destruction. These measures include TLS/HTTPS encryption for all data
            in transit, access controls, and regular security reviews. No method of transmission over the internet or method of electronic
            storage is 100% secure; we cannot guarantee absolute security.
          </p>
        </Section>

        <Section title="8. California Residents — CCPA/CPRA Rights">
          <p className="mb-3">
            If you are a California resident, you have the following rights under the CCPA/CPRA:
          </p>
          <ul className="list-disc list-inside space-y-2 text-white/70">
            <li><strong className="text-white">Right to Know:</strong> Request disclosure of the categories and specific pieces of personal information we have collected about you, the categories of sources, our business purposes for collecting it, and the categories of third parties with whom we share it.</li>
            <li><strong className="text-white">Right to Delete:</strong> Request deletion of personal information we have collected about you, subject to certain legal exceptions.</li>
            <li><strong className="text-white">Right to Correct:</strong> Request correction of inaccurate personal information we maintain about you.</li>
            <li><strong className="text-white">Right to Opt Out of Sale/Sharing:</strong> We do not sell or share your personal information for cross-context behavioral advertising. No opt-out is currently necessary.</li>
            <li><strong className="text-white">Right to Non-Discrimination:</strong> We will not discriminate against you for exercising any of your CCPA/CPRA rights.</li>
          </ul>
          <p className="mt-3">
            To exercise these rights, contact us at <a href={`mailto:${CONTACT_EMAIL}`} className="text-[#00FFC8] hover:underline">{CONTACT_EMAIL}</a>.
            We will respond to verifiable consumer requests within 45 days as required by law.
          </p>
        </Section>

        <Section title="9. Delaware Residents — DOPPA Rights">
          <p>
            If you are a Delaware resident, you have rights under the Delaware Online and Personal Privacy Protection Act,
            including the right to review and request changes to personally identifiable information we have collected about you.
            Contact us at <a href={`mailto:${CONTACT_EMAIL}`} className="text-[#00FFC8] hover:underline">{CONTACT_EMAIL}</a> to exercise
            these rights. We will respond within a reasonable time and notify you of any material changes to this Policy.
          </p>
        </Section>

        <Section title="10. Children&apos;s Privacy">
          <p>
            The Service is not directed to individuals under 16 years of age. We do not knowingly collect personal information from
            children under 16. If we become aware that a child under 16 has provided us personal information, we will delete such
            information promptly. If you believe we may have collected information from a child under 16, contact us immediately at{' '}
            <a href={`mailto:${CONTACT_EMAIL}`} className="text-[#00FFC8] hover:underline">{CONTACT_EMAIL}</a>.
          </p>
        </Section>

        <Section title="11. Changes to This Policy">
          <p>
            We reserve the right to update this Privacy Policy at any time. When we do, we will revise the &ldquo;Last Updated&rdquo; date
            at the top of this page. We will provide additional notice (e.g., a prominent notice on the Service or an email notification)
            if the changes are material. Your continued use of the Service after the effective date of the revised Policy constitutes
            your acceptance of the changes.
          </p>
        </Section>

        <Section title="12. Contact Us">
          <p>
            If you have questions, comments, or concerns about this Privacy Policy or our data practices, please contact us at:
          </p>
          <div className="mt-3 text-white/70">
            <p className="font-semibold text-white">{COMPANY}</p>
            <p>Attn: Privacy Officer</p>
            <p>
              Email:{' '}
              <a href={`mailto:${CONTACT_EMAIL}`} className="text-[#00FFC8] hover:underline">{CONTACT_EMAIL}</a>
            </p>
          </div>
        </Section>

        <div className="mt-16 pt-6 border-t border-white/10 flex flex-col sm:flex-row items-center justify-between gap-2">
          <p className="text-xs text-white/40">
            &copy; {new Date().getFullYear()} {COMPANY}. All rights reserved.
          </p>
          <div className="flex items-center gap-4 text-xs text-white/40">
            <Link href="/privacy" className="text-[#00FFC8]">Privacy Policy</Link>
            <Link href="/terms" className="hover:text-white transition-colors">Terms of Service</Link>
          </div>
        </div>
      </main>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-10">
      <h2 className="text-lg font-semibold text-white mb-3 border-l-2 border-[#00FFC8] pl-3">{title}</h2>
      <div className="text-white/70 text-sm leading-relaxed space-y-2">{children}</div>
    </section>
  );
}

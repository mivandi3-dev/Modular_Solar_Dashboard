// Regresijski testovi sigurnosnih popravaka 4.0 (SECURITY_FINDINGS.json: SMA-xx)
#include <doctest/doctest.h>

#include <windows.h>
#include <aclapi.h>

#include "alerts.hpp"
#include "config.hpp"
#include "util.hpp"

using namespace sm;

TEST_CASE("SMA-01: novi red u postavkama e-pošte ne može dodati curl opciju") {
    Settings s;
    s.smtp_host = "smtp.primjer.hr";
    s.smtp_port = 587;
    s.smtp_user = "solari@primjer.hr";
    const std::vector<std::string> to = {"a@primjer.hr"};
    const std::string ok = curl_mail_config(s, R"(Lo"z\inka)", "solari@primjer.hr", to);
    CHECK(ok == "url = \"smtp://smtp.primjer.hr:587\"\n"
                R"(user = "solari@primjer.hr:Lo\"z\\inka")" "\n"
                "mail-from = \"solari@primjer.hr\"\nmail-rcpt = \"a@primjer.hr\"\n");

    CHECK_THROWS_AS(curl_mail_config(s, "x", "a@b.hr\noutput = \"C:/Windows/x.dll\"", to), MailError);
    CHECK_THROWS_AS(curl_mail_config(s, "x", "a@b.hr", {"c@d.hr\rupload-file = C:/x"}), MailError);
    CHECK_THROWS_AS(curl_mail_config(s, "lo\nzinka", "a@b.hr", to), MailError);
    Settings bad_user = s;
    bad_user.smtp_user = "u\x01";
    CHECK_THROWS_AS(curl_mail_config(bad_user, "x", "a@b.hr", to), MailError);
    Settings bad_host = s;
    bad_host.smtp_host = "smtp.primjer.hr:25/\nproxy = http://zlo";
    CHECK_THROWS_AS(curl_mail_config(bad_host, "x", "a@b.hr", to), MailError);
    bad_host.smtp_host = "smtp.primjer.hr\"";
    CHECK_THROWS_AS(curl_mail_config(bad_host, "x", "a@b.hr", to), MailError);
    CHECK(valid_host_name("192.168.1.10"));
    CHECK(valid_host_name("mail.primjer.hr"));
    CHECK_FALSE(valid_host_name("1.2.3"));
    CHECK_FALSE(valid_host_name("a b"));
}

TEST_CASE("SMA-20: privremena datoteka s lozinkom ne nasljeđuje dozvole mape") {
    wchar_t dir[MAX_PATH];
    GetTempPathW(MAX_PATH, dir);
    const fs::path p = fs::path(dir) / L"solari_private_test.cfg";
    std::error_code ec;
    fs::remove(p, ec);
    write_private_file(p, "tajna");
    CHECK(read_file(p).value_or("") == "tajna");
    CHECK_THROWS(write_private_file(p, "drugo"));  // CREATE_NEW: postojeća (podmetnuta) datoteka se ne koristi
    PSECURITY_DESCRIPTOR sd = nullptr;
    PACL dacl = nullptr;
    REQUIRE(GetNamedSecurityInfoW(p.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &sd) ==
            ERROR_SUCCESS);
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD rev = 0;
    GetSecurityDescriptorControl(sd, &control, &rev);
    CHECK((control & SE_DACL_PROTECTED) != 0);
    CHECK(dacl->AceCount == 3);
    LocalFree(sd);
    fs::remove(p, ec);
}

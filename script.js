$(document).ready(function () {
    $('#surveyForm').submit(function (event) {
        if ($('#WPSYes').is(':checked')) {
            
            //cant submit blank wps Q
            var wpsModes = $('input[name="WPSMode"]:checked');
            if (wpsModes.length === 0) {
                alert('Please select at least one WPS mode.');
                event.preventDefault();
                return;
            }
        }

        //cant submit blank password complexity Q
        var complexityOptions = $('#passwordComplexityDiv .form-check-input:checked');
        if (complexityOptions.length === 0) {
            alert('Please select at least one complexity option for your password.');
            event.preventDefault();
            return;
        }
        
        event.preventDefault();

        sessionStorage.setItem('securityProtocol', $('#securityType').val());
        sessionStorage.setItem('passwordLength', $('#passwordLength').val());
        sessionStorage.setItem('hasUppercase', $('#uppercaseLetters').is(':checked'));
        sessionStorage.setItem('hasNumbers', $('#numbers').is(':checked'));
        sessionStorage.setItem('hasSymbols', $('#symbols').is(':checked'));
        sessionStorage.setItem('dictionaryAttack', $('input[name=dictionaryAttack]:checked').val());
        sessionStorage.setItem('passwordProtected', $('input[name=passwordProtected]:checked').val());
        sessionStorage.setItem('physicalSecurity', $('input[name="physicalSecurity"]:checked').val());
        sessionStorage.setItem('WPSInUse', $('input[name="WPS"]:checked').val());
        sessionStorage.setItem('WPSModePIN', $('#WPSModePIN').is(':checked'));
        sessionStorage.setItem('WPSModePushButton', $('#WPSModePushButton').is(':checked').toString());
        sessionStorage.setItem('regularlyApplyingUpdates', $('input[name="networkUpdates"]:checked').val());      
        
        //send to report page
        window.location.href = '/report.html';
        });

    if (window.location.pathname === '/report.html') {
        var securityProtocol = sessionStorage.getItem('securityProtocol');
        var passwordProtected = sessionStorage.getItem('passwordProtected') === 'yes';

        var krackAttackItem = document.getElementById("headingKRACK");
        var dragonbloodAttackItem = document.getElementById("headingDragonblood");

        krackAttackItem.style.display = "none";
        dragonbloodAttackItem.style.display = "none";
    
        if (securityProtocol === "WPA" || securityProtocol === "WPA2") {
            krackAttackItem.style.display = "block";
        } else if (securityProtocol === "WPA3") {
            dragonbloodAttackItem.style.display = "block";
        }
        
        if (!passwordProtected) {
            $('#noPasswordWarning').show();
            $('#passwordCheck').hide();

            var riskLevelColor = 'red';
            var riskLevelText = 'Increased';

        }
        // come back to this!!!!
        else{
        var protocolAnalysis = '';
        if (securityProtocol === 'WEP') {
            protocolAnalysis = '<p>WEP (Wired Equivalent Privacy) was the first attempt at Wi-Fi security in 1997 and has been deprecated since the release of WPA2 in 2004. It has MAJOR security flaws that make attacks that could decrypt traffic and reveal sensitive information trivial. An example of one of these attacks is the Beck-Tews attack, which can be seen <a href="https://eprint.iacr.org/2008/472.pdf">here</a>. There is no situation where WEP should still be used. If your router or access point(s) only support WEP, you should strongly consider purchasing new networking equipment.</p>';

            protocolRating = 'Poor';
            protocolRatingColor = 'red';
        } else if (securityProtocol === 'WPA') {
            protocolAnalysis = '<p>WPA (Wi-Fi Protected Access) was introduced in 2003 as a temporary protocol to address critical security shortcomings found in WEP. While it is more secure than WEP, WPA has a number of flaws and should not be used anymore. Because it was designed to function on older hardware running WEP, it is still vulnerable to several of the attacks that affected WEP, such as the Beck-Tews attack, which can be seen <a href="https://eprint.iacr.org/2008/472.pdf">here</a>. The protocol was deprecated by the Wi-Fi Alliance in 2015, and, ideally, you should use WPA3 if possible, but if you must use WPA2, be sure to use a long, complex password without common words or phrases to protect yourself against common attacks.</p>';
            protocolRating = 'Poor';
            protocolRatingColor = 'red';
        } else if (securityProtocol === 'WPA2') {
            protocolAnalysis = '<p>WPA2 (Wi-Fi Protected Access 2) released in 2004 and was not superseded until the release of 2018. It replaced WPA and uses much stronger stronger cryptography and solved many of the problems that were present with WEP and WPA. However, WPA2 is susceptible to a number of attacks, notably password cracking attacks and the infamous KRACK attacks that were discovered in 2017. Upgrading to WPA3 solves many of the shortcomings of WPA2 and should strongly be considered.</p>';
            protocolRating = 'Average';
            protocolRatingColor = 'orange';
        } else if (securityProtocol === 'WPA3') {
            protocolAnalysis = '<p>WPA3 (Wi-Fi Protected Access 3) is the most recent security protocol for Wi-Fi released by the Wi-Fi Alliance in 2018. It provides several improvements over WPA2, including protection against offline password cracking attacks and perfect forward secrecy. WPA3 replaced the 4-way handshake used by WPA and WPA2 in favor of the Simultaneous Authentication of Equals (SAE), also known as the Dragonfly Handshake, which protects WPA3-secured networks from many of the attacks that have historically targeted Wi-Fi networks. Good choice! .</p>';
            protocolRating = 'Great';
            protocolRatingColor = 'green';
        } else {
            protocolAnalysis = '<p>Unknown security protocol. Please go back and select a security protocol.</p>';
            protocolRating = 'Unknown';
            protocolRatingColor = 'black';
        }
        
        protocolAnalysis += '<p>Protocol Security Rating: <span style="color:' + protocolRatingColor + ';">' + protocolRating + '</span></p>';

        $('#protocolAnalysisDiv').html(protocolAnalysis);
        
        // This stuff is used for the brute force time calcs
        var passwordLength = parseInt(sessionStorage.getItem('passwordLength'));
        var hasUppercase = sessionStorage.getItem('hasUppercase') === 'true';
        var hasNumbers = sessionStorage.getItem('hasNumbers') === 'true';
        var hasSymbols = sessionStorage.getItem('hasSymbols') === 'true';
        var isUsingCommonWords = sessionStorage.getItem('dictionaryAttack') === 'yes';

        var complexity;
        if (hasNumbers && hasUppercase && hasSymbols) {
            complexity = 'Numbers and Upper and Lowercase Letters and Symbols';
        } else if (hasNumbers && hasUppercase) {
            complexity = 'Numbers and Upper and Lowercase Letters';
        } else if (hasUppercase) {
            complexity = 'Upper and Lowercase Letters';
        } else if (hasNumbers) {
            complexity = 'Numbers Only';
        } else {
            complexity = 'Lowercase Letters';
        }
        
        var passwordAnalysis = analyzePassword(passwordLength, complexity);

        $('#passwordAnalysis').html(passwordAnalysis);
        
        // https://www.hivesystems.io/blog/are-your-passwords-in-the-green

        
        function analyzePassword(passwordLength, complexity) {
            //numbers only, lowercase only, upper only, lower and upper and nums, everything
            var times = [
                ['0 seconds', '0 seconds', '0 seconds', '0 seconds', '0 seconds'], 
                ['0 seconds', '0 seconds', '0 seconds', '0 seconds', '0 seconds'], 
                ['0 seconds', '0 seconds', '0 seconds', '0 seconds', '0 seconds'], 
                ['0 seconds', '0 seconds', '1 second', '2 seconds', '4 seconds'], 
                ['0 seconds', '0 seconds', '28 seconds', '2 minutes', '5 minutes'], 
                ['0 seconds', '3 seconds', '24 minutes', '2 hours', '6 hours'],
                ['0 seconds', '1 minute', '21 hours', '5 days', '2 weeks'],
                ['1 second', '32 minutes', '1 month', '10 months', '3 years'],
                ['6 seconds', '14 hours', '6 years', '53 years', '226 years'],
                ['5 seconds', '2 weeks', '332 years', '3 thousand years', '15 thousand years'],
                ['52 seconds', '1 year', '17 thousand years', '202 thousand years', '1 million years'],
                ['9 minutes', '27 years', '898 thousand years', '12 million years', '77 million years'],
                ['1 hour', '713 years', '46 million years', '779 million years', '5 billion years'],
                ['14 hours', '18 thousand years', '2 billion years', '48 billion years', '380 billion years'],
                ['6 days', '481 thousand years', '126 billion years', '2 trillion years', '26 trillion years']
            ];
            
        
            var pwComplexity;
            switch (complexity) {
            case 'Numbers Only':
                pwComplexity = 0;
                break;
            case 'Lowercase Letters':
                pwComplexity = 1;
                break;
            case 'Upper and Lowercase Letters':
                pwComplexity = 2;
                break;
            case 'Numbers and Upper and Lowercase Letters':
                pwComplexity = 3;
                break;
            case 'Numbers and Upper and Lowercase Letters and Symbols':
                pwComplexity = 4;
                break;
        }
    
        var timeToCrack = times[passwordLength - 4][pwComplexity];
        
        var bruteForceRiskLevel;
        var riskLevelColor;

        if (securityProtocol === 'WPA3') {
            bruteForceRiskLevel = 'Reduced';
            riskLevelColor = 'green';
            //COME BACK HERE!!!!
        } else if (timeToCrack === 'Instantly' || /second(s)?$/.test(timeToCrack) || /minute(s)?$/.test(timeToCrack) || /hour(s)?$/.test(timeToCrack) || /day(s)?$/.test(timeToCrack)) {
            bruteForceRiskLevel = 'Increased';
            riskLevelColor = 'red';
        } else {
            bruteForceRiskLevel = 'Normal';
            riskLevelColor = 'orange';
        }

        $('#bruteForceRiskLevel').html('<span style="color:' + riskLevelColor + ';">' + bruteForceRiskLevel + '</span>');
        
        var recommendations;

        if (bruteForceRiskLevel === 'Reduced') {
            recommendations = '<p>Your network is dramatically less likely to be affected by a brute-force attack because you are using the WPA3 protocol, which is designed to make password cracking attacks like a brute force attack infeasible, or your password complexity and length meets high security standards.</p>';
        } else if (bruteForceRiskLevel === 'Normal') {
            recommendations = '<p>Your network is relatively safe from being compromised by a brute-force attack. The length and complexity of your password are good, but migrating to the WPA3 protocol would provide even stronger protection as it is specifically designed to make password cracking attacks like brute-force attacks infeasibles.</p>';
        } else if (bruteForceRiskLevel === 'Increased') {
            recommendations = '<p>Your current Wi-Fi password is inadequate, leading to an increased risk for brute-force attacks. Consider migrating to the WPA3 protocol as it is specifically designed to make password cracking attacks like a brute-force attack infeasible. If this is not possible, consider increasing the length and complexity of your current password. Each character of length that is added to a password exponentially increases the time it takes to brute-force! </p>';
        }

        $('#bruteForcePasswordRec').html(recommendations);
        var analysis = '';

        if (securityProtocol === 'WPA3') {
            analysis += '<p>WPA3 (Wi-Fi Protected Access 3) is the latest security protocol for wireless networks. It introduces significant improvements in security compared to previous versions. One of the key features of WPA3 is its resistance to password cracking attempts, even if an attacker captures data from your network. This is achieved through the use of the Simultaneous Authentication of Equals (SAE) handshake, nicknamed Dragonfly handshake, which replaces the 4-way handshake method used in previous versions. SAE ensures that an attacker cannot perform offline brute-force attacks on the captured data, making password cracking infeasible.</p>';

        }
        else if(securityProtocol != 'WPA3') {
            var timeToCrack = times[passwordLength - 4][pwComplexity];
            analysis += 'Based on the length and complexity of your password, it would take approximately ' + timeToCrack + ' to brute-force it using modern, accessible, consumer-grade equipment. This time could be exponentially decreased if the attacker has access to more powerful hardware or cloud computing resources (calculation based on Hive Systems data).';    
        }

        return analysis;
    }

    //Dictionary Attack stuff
    var dictionaryRiskLevel;
    var dictionaryRiskLevelColor;

    if (securityProtocol === 'WPA3') {
        dictionaryRiskLevel = 'Reduced';
        dictionaryRiskLevelColor = 'green';
        $('#dictionaryAttackRec').html('<p>Your network is well-protected against dictionary attacks. You have chosen strong security measures, such as using WPA3 and avoiding common words or phrases in your password.</p>');
    } else if (isUsingCommonWords) {
        dictionaryRiskLevel = 'Increased';
        dictionaryRiskLevelColor = 'red';
        $('#dictionaryAttackRec').html('<p>Using common words in your password makes it vulnerable to dictionary attacks. This greatly increases the chance of your password being cracked by an unauthorized party.</p>');
    } else {
        dictionaryRiskLevel = 'Normal';
        dictionaryRiskLevelColor = 'orange';
        $('#dictionaryAttackRec').html('<p>Your avoidance of common words or phrases in your password is protecting you against your password being cracked by a dictionary attack, but upgrading to WPA3 can further reduce your risk as it is resistant to common password cracking techniques.</p>');
    }

    $('#dictionaryAttackRiskLevel').html('<span style="color:' + dictionaryRiskLevelColor + ';">' + dictionaryRiskLevel + '</span>');
        

    // Rogue Access Points Stuff
    var physicalSecurity = sessionStorage.getItem('physicalSecurity');

    analyzeRogueAPAttack(physicalSecurity, securityProtocol);

    function analyzeRogueAPAttack(physicalSecurity) {
        var APRiskLevel;
        var APRiskLevelColor;
        var recommendations = '';
    
        if (physicalSecurity === 'yes') {
            APRiskLevel = 'Reduced';
            APRiskLevelColor = 'green';
            recommendations += 'Continue to keep your networking equipment in a secure location to prevent someone from connecting an unauthorized access point to your network.';
        } else {
            APRiskLevel = 'Increased';
            APRiskLevelColor = 'red';
            recommendations += 'You should place your router and other networking devices in a secure location to reduce the risk of rogue access points being added to your network.';
        }
        
    
        $('#rogueAPRiskLevel').html('<span style="color:' + APRiskLevelColor + ';">' + APRiskLevel + '</span>');
        $('#rogueAPRec').html(recommendations);
    }

    /// reuse this for a couple things - general representation of difficulty for someone to get on netwrok
var protocolHybridRiskLevel;
var protocolHybridRiskLevelColor;

if (securityProtocol === 'WEP' || securityProtocol === 'WPA') {
    protocolHybridRiskLevel = 'Increased';
    protocolHybridRiskLevelColor = 'red';
} else if (securityProtocol === 'WPA3') {
    protocolHybridRiskLevel = 'Reduced';
    protocolHybridRiskLevelColor = 'green';
} else if (securityProtocol === 'WPA2') {
    if (bruteForceRiskLevel === 'Reduced' && !isUsingCommonWords) {
        protocolHybridRiskLevel = 'Reduced';
        protocolHybridRiskLevelColor = 'green';
    } else {
        protocolHybridRiskLevel = 'Normal';
        protocolHybridRiskLevelColor = 'orange';
    }
 
}

//reuse the hybrid one
var packetSniffingRecommendation;

if (protocolHybridRiskLevel === 'Increased') {
    packetSniffingRecommendation = '<p>Your network is at increased risk for a bad actor maliciously using a packet sniffer to view your network traffic. If a bad actor is able to get connected to your network, packet sniffing is very easy to perform. Using WPA3 can help prevent this as it is resistant to common password cracking techniques and can help keep bad actors from gaining access to your network in the first place. Using a long, complex Wi-Fi password can also help keep bad actors from connecting to your network to perform packet sniffing. Additionally, WPA 3 incorporates something called Perfect Forward Secrecy (PFS), a concept that ensures that the if one session key gets compromised, future sessions will not be able to be decrypted with the compromised key.</p>';
} else if (protocolHybridRiskLevel === 'Normal') {
    packetSniffingRecommendation = '<p>Your network is fairly safe from packet sniffing, but there is room for improvement. Consider upgrading to WPA3 or enhancing the strength of your Wi-Fi password to help prevent bad actors from connecting to your network. Once a bad actor is connected to your network, packet sniffing very easy to perform. Additionally, WPA 3 incorporates something called Perfect Forward Secrecy (PFS), a concept that ensures that the if one session key gets compromised, future sessions will not be able to be decrypted with the compromised key.</p>';
} else if (protocolHybridRiskLevel === 'Reduced') {
    packetSniffingRecommendation = '<p>Your network is well protected against packet sniffing. You have chosen strong security measures, such as using WPA3 and/or a robust password!</p>';
}
    
    $('#packetSniffingRiskLevel').html('<span style="color:' + protocolHybridRiskLevelColor + ';">' + protocolHybridRiskLevel + '</span>');
    $('#packetSniffingRec').html(packetSniffingRecommendation);
    

    $('#mitmRiskLevel').html('<span style="color:' + protocolHybridRiskLevelColor + ';">' + protocolHybridRiskLevel + '</span>');

    //reuse hybrid 
var mitmRecommendations;
if (protocolHybridRiskLevel === 'Increased') {
    mitmRecommendations = '<p>Your network has an increased risk for Man-in-the-Middle attacks. Consider upgrading to WPA3 and strengthening your password to significantly reduce this risk. Attackers typically need to be connected to the same network as you to carry out this type of attack, so preventing them from connecting in the first place is a good defense.</p>';
} else if (protocolHybridRiskLevel === 'Normal') {
    mitmRecommendations = '<p>Your network has a moderate risk for Man-in-the-Middle attacks. Upgrading to WPA3 or enhancing your password can help further protect you from bad actors connnecting to your network and performing a man-in-the-middle attack. You should still be mindful of the websites you visit and ensure they are using secure connections. Do not ignore certificate errors when visiting websites as it may be a sign a man-in-the-middle attack is occuring. Attackers typically need to be connected to the same network as you to carry out this type of attack, so preventing them from connecting in the first place is a good defense.</p>'
} else if (protocolHybridRiskLevel === 'Reduced') {
    mitmRecommendations = '<p>Your network is well-protected against Man-in-the-Middle attacks. Despite this, you should still be mindful of the websites you visit and ensure they are using secure connections. Do not ignore certificate errors when visiting websites as it may be a sign a man-in-the-middle attack is occuring.</p>';
}

$('#mitmRecommendations').html(mitmRecommendations);

// phys sec
var physicalSecurity = sessionStorage.getItem('physicalSecurity');
var physicalAccessRiskLevel;
var physicalAccessRiskLevelColor;

if (physicalSecurity === 'yes') {
    physicalAccessRiskLevel = 'Reduced';
    physicalAccessRiskLevelColor = 'green';
    $('#physicalAccessRec').html('<p>Your network equipment being in a secure location reduces the risk of someone making an unauthorized wired connection to your network. Only people you trust should have access to the equipment.</p>');
} else {
    physicalAccessRiskLevel = 'Increased';
    physicalAccessRiskLevelColor = 'red';
    $('#physicalAccessRec').html('<p>Consider placing your router and other network devices in a secure location. Being in an insecure location increases the chance that someone could make an unauthorized wired connection to your network, which would pypass any Wi-Fi security controls you have in place. Only people you trust should have access to the equipment..</p>');
}

$('#physicalAccessRiskLevel').html('<span style="color:' + physicalAccessRiskLevelColor + ';">' + physicalAccessRiskLevel + '</span>');

var WPSInUse = sessionStorage.getItem('WPSInUse') === 'yes';
var WPSModePIN = sessionStorage.getItem('WPSModePIN') === 'true';
var WPSModePushButton = sessionStorage.getItem('WPSModePushButton') === 'true';
var physicalSecurity = sessionStorage.getItem('physicalSecurity');
var WPSRiskLevel;
var WPSRiskLevelColor;
var WPSRecommendation;

// if pin is on at all, increased - if push is on, check if physical sec is good (yes = reduced, no = inc), if wps off reduced
if (WPSInUse) {
    if (WPSModePIN && WPSModePushButton) {
        WPSRiskLevel = 'Increased';
        WPSRiskLevelColor = 'red';
        WPSRecommendation = 'The PIN mode of WPS is vulnerable to brute force attacks and should no longer be used. You should disable this mode if possible. If it cannot be, consider disabling WPS altogether';
    } else if (WPSModePIN && !WPSModePushButton) {
        WPSRiskLevel = 'Increased';
        WPSRiskLevelColor = 'red';
        WPSRecommendation = 'The PIN mode of WPS is vulnerable to brute force attacks and should no longer be used. You should disable this mode if possible. If it cannot be, consider disabling WPS altogether';
    } else if (!WPSModePIN && WPSModePushButton) {
        if (physicalSecurity === 'no') {
            WPSRiskLevel = 'Increased';
            WPSRiskLevelColor = 'red';
            WPSRecommendation = 'If a bad actor is able to press the WPS button on your networking device, they will be able to connect easily. If you would like to continue using this functionality, consider placing the device with the WPS button in a secure location to avoid unauthorized users from connecting devices to your network.';
        } else {
            WPSRiskLevel = 'Reduced';
            WPSRiskLevelColor = 'green';
            WPSRecommendation = 'Since you are not using the PIN mode of WPS, which is vulnerable to brute force attacks, and your networking device is in a secure location, the risk of unauthorized users connecting to your network using the WPS Push Button is reduced.';
        }
    }
    //no wps case
    } else {
        WPSRiskLevel = 'Reduced';
        WPSRiskLevelColor = 'green';
        WPSRecommendation = 'Since you are not using WPS, these attacks do not affect your environment.';
    }


$('#WPSRiskLevel').html('<span style="color:' + WPSRiskLevelColor + ';">' + WPSRiskLevel + '</span>');
$('#WPSRecommendation').html(WPSRecommendation);

}
    // reuse the patching question for the dragonbloods, kracks, and FRAGS
    var isRegularlyPatching = sessionStorage.getItem('regularlyApplyingUpdates') === 'yes';
    var riskLevel;
    var riskLevelColor;
    var recommendation;

    if (isRegularlyPatching) {
        riskLevel = 'Reduced';
        riskLevelColor = 'green';
        recommendation = 'Since you are regularly applying security patches or have autoupdates enabled on your networking equipment, you have likely already applied relevant patches and mitigated the risk. Continue to make sure security patches are regularly applied to maintain network security.';

        var dragonbloodRecommendation = recommendation + ' Consider disabling WPA3-Transition mode if it is enabled to further reduce your risk.';
    } else {
        riskLevel = 'Increased';
        riskLevelColor = 'red';
        recommendation = 'Review published patches from the manufacturer for your router or access points and compare them to the firmware version of your device to see if you are affected. Regularly applying updates is essential to maintain security.';

        // do the dragons separately to tell them to turn off transition
        var dragonbloodRecommendation = recommendation + ' Additionally, consider disabling WPA3-Transition mode if it is enabled to further reduce risk of a downgrade attack.';
    }

        $('#KRACKRiskLevel, #FRAGRiskLevel').html('<span style="color:' + riskLevelColor + ';">' + riskLevel + '</span>');
        $('#KRACKRec, #FRAGRec').html('<p>' + recommendation + '</p>');

        $('#dragonRiskLevel').html('<span style="color:' + riskLevelColor + ';">' + riskLevel + '</span>');
        $('#dragonRec').html('<p>' + dragonbloodRecommendation + '</p>');
    
}

    $('#lowercaseLetters').prop('checked', true);
    

    function toggleRequiredFields(isProtected) {
        $("#securityType").prop("required", isProtected);
        $("#passwordLength").prop("required", isProtected);
        $("input[name=dictionaryAttack]").prop("required", isProtected);
    }

    $('#passwordYes').change(function () {
        if ($(this).is(':checked')) {
            $('#securityProtocolDiv, #dictionaryAttackDiv, #passwordLengthDiv, #passwordComplexityDiv').show();
            password = true;
            toggleRequiredFields(true);
        }
    });

    $('#passwordNo').change(function () {
        if ($(this).is(':checked')) {
            $('#securityProtocolDiv, #dictionaryAttackDiv, #passwordLengthDiv, #passwordComplexityDiv').hide();            password = false;
            toggleRequiredFields(false);
        }
    });

    $('#securityType').change(function () {
        var selectedProtocol = $(this).val();
        if (selectedProtocol) {
            $('#passwordLengthDiv').show();
        } else {
            $('#passwordLengthDiv').hide();
        }
    });

    $('input[name="WPS"]').change(function() {
        if ($('#WPSYes').is(':checked')) {
            $('#WPSModeDiv').show();
        } else {
            $('#WPSModeDiv').hide();
        }
    });

    // COME BACK HERE NOT WORKING!!!
    if ($('#vulnerabilitiesTable').length) {
        $('#vulnerabilitiesTable').css('display', 'table');
        $('#vulnerabilitiesTable').DataTable({
            destroy: true,
            ajax: {
                url: 'get_data.php',
                type: 'GET',
                //type: 'POST',
                dataSrc: '',
                dataType: 'json'
            },
            columns: [
                { data: 'threat_name' },
                { data: 'threat_id', render: function (data, type, row) { return '<a href="' + row.threat_id_link + '">' + data + '</a>'; } },
                { data: 'summary' },
                //{data: 'impact'}, 
                { data: 'cvss_score' },
                { data: 'attack_documentation' }
            ]
        });
    }
});
$(document).ready(function(){

    function CognitoUtil () {

        //idToken, accessToken, refreshToken
        this.accessToken = '';
        this.idToken = '';
        this.refreshToken = '';

        this.init = function(result) {

            this.accessToken = result.getAccessToken().getJwtToken();
            this.idToken = result.getIdToken().getJwtToken();
            // this.refreshToken = result.getRefreshToken().getJwtToken();

            // this.accessToken = jwtToken.split('.')[0];
            // this.idToken = jwtToken.split('.')[1];
            // this.refreshToken = jwtToken.split('.')[2];


        };

        this.getExpiration = function() {

            const idToken = this.idToken.split('.')[1];

            const decoded = JSON.parse((window.atob(idToken)).toString('utf8'));
            return decoded.exp;

        }
    }

    const cognitoData = {

        identityPoolId: 'us-east-1:XXXXccfe-YYYY-468b-ZZZZ-AAAAnea6AAAA',
        userPoolId: 'us-east-1_AAAABBBBe',
        clientId: 'AAAABBBBCCCCDDDDEEEEddg9gm'
    };

    const REGION = 'us-east-1';

    // Set the region where your identity pool exists (us-east-1, eu-west-1)
    AWS.config.update({region: REGION});

    /**
     *
     * @type {CognitoUserPool}
     */
    const userPool = new AWSCognito.CognitoIdentityServiceProvider.CognitoUserPool({
        UserPoolId : cognitoData.userPoolId,
        ClientId : cognitoData.clientId
    });

    const cognitoUtil = new CognitoUtil();

    /**
     *
     */
    function registerUser() {

        var username =      $('#txtUsername').val();
        var password =      $('#txtPassword').val();
        var email =         $('#txtEmail').val();
        var phoneNumber =   $('#txtPhoneNumber').val();

        var attributeList = [];

        var dataEmail = {
            Name : 'email',
            Value : email //'jlamadri+a@amazon.com'
        };

        var dataPhoneNumber = {
            Name : 'phone_number',
            Value : phoneNumber //'+15555550000'
        };

        var attributeEmail = new AWSCognito.CognitoIdentityServiceProvider.CognitoUserAttribute(dataEmail);
        var attributePhoneNumber = new AWSCognito.CognitoIdentityServiceProvider.CognitoUserAttribute(dataPhoneNumber);

        attributeList.push(attributeEmail);
        attributeList.push(attributePhoneNumber);

        userPool.signUp(username, password, attributeList, null, function(err, result){

            if (err) {
                alert(err);
                return;
            }

            cognitoUser = result.user;

            $('#msgRegistered').text('Registered user: ' + cognitoUser.getUsername());

            $('#txtUsernameConfirm').val(cognitoUser.getUsername());
        });

    }

    function confirmUser(e){

        e.preventDefault();

        var username =          $('#txtUsernameConfirm').val();
        var confirmationCode =  $('#txtConfirmationCode').val();

        const userData = {
            Username: username,
            Pool: userPool
        };

        const cognitoUser = new AWSCognito.CognitoIdentityServiceProvider.CognitoUser(userData);

        cognitoUser.confirmRegistration(confirmationCode, true, function (err, result) {
            if (err) {
                $('#msgConfirmed').text('Error confirming user: ' + err.message);
            } else {
                $('#msgConfirmed').text('Confirmed user: ' + result);
            }
        });
    }

    /**
     *
     */
    function authenticate(){

        var username = $('#txtUsernameLogin').val();
        var password = $('#txtPasswordLogin').val();

        // Need to provide placeholder keys unless unauthorised user access is enabled for user pool
        AWSCognito.config.update({accessKeyId: 'anything', secretAccessKey: 'anything'});

        const authenticationData = {
            Username: username,
            Password: password
        };

        const authenticationDetails = new AWSCognito.CognitoIdentityServiceProvider.AuthenticationDetails(authenticationData);

        const userData = {
            Username: username,
            Pool: userPool
        };

        const cognitoUser = new AWSCognito.CognitoIdentityServiceProvider.CognitoUser(userData);

        cognitoUser.authenticateUser(authenticationDetails, {

            onSuccess: function (result) {

                const jwtToken = result.getIdToken().getJwtToken();

                cognitoUtil.init(result);

                const logins = {};

                logins['cognito-idp.' + REGION + '.amazonaws.com/' + cognitoData.userPoolId]
                    = jwtToken;

                // Add the User's Id Token to the Cognito credentials login map.
                AWS.config.credentials = new AWS.CognitoIdentityCredentials({
                    IdentityPoolId: cognitoData.identityPoolId,
                    Logins: logins
                });

                // Instantiate aws sdk service objects now that the credentials have been updated.
                // example: var s3 = new AWS.S3();

                console.log('AWS credentials - ' + JSON.stringify(AWS.config.credentials));

                console.log('AWS Cognito credentials - ' + JSON.stringify(AWSCognito.config.credentials));

                AWS.config.credentials.get(function (err) {
                    if (!err) {
                        var jsonPretty = JSON.stringify(result, null, '\t');
                        $('#modalBody').text(jsonPretty);
                        $('#exampleModalLong').modal({})
                    } else {
                        $('#msgLogin').text(err.message);
                    }
                });

            },

            onFailure: function (err) {
                $('#msgLogin').text(err.message);
            }
        });



    }

    function faceBookLogin(){


        FB.login(function (response) {

            // Check if the user logged in successfully.
            if (response.authResponse) {

                console.log('You are now logged in.');

                // Add the Facebook access token to the Cognito credentials login map.
                AWS.config.credentials = new AWS.CognitoIdentityCredentials({
                    IdentityPoolId: cognitoData.identityPoolId,
                    Logins: {
                        'graph.facebook.com': response.authResponse.accessToken
                    }
                });

                // Obtain AWS credentials
                AWS.config.credentials.get(function(err){
                    // Access AWS resources here.
                    if (!err) {
                        var jsonPretty = JSON.stringify(response, null, '\t');
                        $('#modalBody').text(jsonPretty);
                        $('#exampleModalLong').modal({})
                    } else {
                        $('#msgLogin').text(err.message);
                    }
                });

                console.log('Welcome!  Fetching your information.... ');
                FB.api('/me', {fields: 'name, email'}, function(response) {
                    console.log('Good to see you, ' + response.name + '.');
                });

            } else {
                console.log('There was a problem logging you in.');
            }

        }, {scope: 'email, public_profile', return_scopes: true});
    }

    function getCurrentUser() {
        return this.getUserPool().getCurrentUser();
    }

    function getTempCredentials(){

        // Configure the credentials provider to use your identity pool
        AWS.config.credentials = new AWS.CognitoIdentityCredentials({
            IdentityPoolId: cognitoData.identityPoolId
        });

        // Make the call to obtain credentials
        AWS.config.credentials.get(function(){

            // Credentials will be available when this function is called.
            var accessKeyId = AWS.config.credentials.accessKeyId;
            var secretAccessKey = AWS.config.credentials.secretAccessKey;
            var sessionToken = AWS.config.credentials.sessionToken;

            console.log(accessKeyId, secretAccessKey, sessionToken);

        });
    }

    function listInstances() {

        // Create an S3 client
        var s3 = new AWS.S3();

        var ec2 = new AWS.EC2();
        ec2.describeInstances({}, function(err, data) {
            if (err) {
                console.log(err, err.stack);
                $('#msgEC2').text(err);
            } else {

                var jsonPretty = JSON.stringify(data.Reservations, null, '\t');
                $('#modalBody').text(jsonPretty);
                $('#exampleModalLong').modal({})
            }
        });
    }


    // ----- listener registration -------

    $("#btnRegisterUser").on("click", function(){
        registerUser();
    });

    $("#btnConfirmUser").on("click", function(e){
        confirmUser(e);
    });

    $("#btnLogin").on("click", function(){
        authenticate();
    });

    $("#btnListEC2Instances").on("click", function(){
        listInstances();
    });

    $("#btnLoginFacebook").on("click", function(){
        faceBookLogin();
    });


});
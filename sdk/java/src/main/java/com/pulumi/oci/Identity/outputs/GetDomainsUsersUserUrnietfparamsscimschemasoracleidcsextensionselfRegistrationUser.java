// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Identity.outputs.GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUserSelfRegistrationProfile;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUser {
    /**
     * @return A boolean value that indicates whether the consent is granted.
     * 
     */
    private Boolean consentGranted;
    /**
     * @return Self registration profile used when user is self registered.
     * 
     */
    private List<GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUserSelfRegistrationProfile> selfRegistrationProfiles;
    /**
     * @return User token returned if userFlowControlledByExternalClient is true
     * 
     */
    private String userToken;

    private GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUser() {}
    /**
     * @return A boolean value that indicates whether the consent is granted.
     * 
     */
    public Boolean consentGranted() {
        return this.consentGranted;
    }
    /**
     * @return Self registration profile used when user is self registered.
     * 
     */
    public List<GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUserSelfRegistrationProfile> selfRegistrationProfiles() {
        return this.selfRegistrationProfiles;
    }
    /**
     * @return User token returned if userFlowControlledByExternalClient is true
     * 
     */
    public String userToken() {
        return this.userToken;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUser defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean consentGranted;
        private List<GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUserSelfRegistrationProfile> selfRegistrationProfiles;
        private String userToken;
        public Builder() {}
        public Builder(GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUser defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.consentGranted = defaults.consentGranted;
    	      this.selfRegistrationProfiles = defaults.selfRegistrationProfiles;
    	      this.userToken = defaults.userToken;
        }

        @CustomType.Setter
        public Builder consentGranted(Boolean consentGranted) {
            this.consentGranted = Objects.requireNonNull(consentGranted);
            return this;
        }
        @CustomType.Setter
        public Builder selfRegistrationProfiles(List<GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUserSelfRegistrationProfile> selfRegistrationProfiles) {
            this.selfRegistrationProfiles = Objects.requireNonNull(selfRegistrationProfiles);
            return this;
        }
        public Builder selfRegistrationProfiles(GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUserSelfRegistrationProfile... selfRegistrationProfiles) {
            return selfRegistrationProfiles(List.of(selfRegistrationProfiles));
        }
        @CustomType.Setter
        public Builder userToken(String userToken) {
            this.userToken = Objects.requireNonNull(userToken);
            return this;
        }
        public GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUser build() {
            final var o = new GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfRegistrationUser();
            o.consentGranted = consentGranted;
            o.selfRegistrationProfiles = selfRegistrationProfiles;
            o.userToken = userToken;
            return o;
        }
    }
}
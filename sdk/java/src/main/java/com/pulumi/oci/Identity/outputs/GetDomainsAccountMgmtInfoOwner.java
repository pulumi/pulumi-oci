// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsAccountMgmtInfoOwner {
    /**
     * @return Resource Type display name
     * 
     */
    private String display;
    /**
     * @return The email address of this user
     * 
     */
    private String email;
    /**
     * @return UserWalletArtifact URI
     * 
     */
    private String ref;
    /**
     * @return User name
     * 
     */
    private String userName;
    /**
     * @return UserWalletArtifact identifier
     * 
     */
    private String value;

    private GetDomainsAccountMgmtInfoOwner() {}
    /**
     * @return Resource Type display name
     * 
     */
    public String display() {
        return this.display;
    }
    /**
     * @return The email address of this user
     * 
     */
    public String email() {
        return this.email;
    }
    /**
     * @return UserWalletArtifact URI
     * 
     */
    public String ref() {
        return this.ref;
    }
    /**
     * @return User name
     * 
     */
    public String userName() {
        return this.userName;
    }
    /**
     * @return UserWalletArtifact identifier
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsAccountMgmtInfoOwner defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String display;
        private String email;
        private String ref;
        private String userName;
        private String value;
        public Builder() {}
        public Builder(GetDomainsAccountMgmtInfoOwner defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.display = defaults.display;
    	      this.email = defaults.email;
    	      this.ref = defaults.ref;
    	      this.userName = defaults.userName;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder display(String display) {
            this.display = Objects.requireNonNull(display);
            return this;
        }
        @CustomType.Setter
        public Builder email(String email) {
            this.email = Objects.requireNonNull(email);
            return this;
        }
        @CustomType.Setter
        public Builder ref(String ref) {
            this.ref = Objects.requireNonNull(ref);
            return this;
        }
        @CustomType.Setter
        public Builder userName(String userName) {
            this.userName = Objects.requireNonNull(userName);
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        public GetDomainsAccountMgmtInfoOwner build() {
            final var o = new GetDomainsAccountMgmtInfoOwner();
            o.display = display;
            o.email = email;
            o.ref = ref;
            o.userName = userName;
            o.value = value;
            return o;
        }
    }
}
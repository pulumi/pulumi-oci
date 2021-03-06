// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Bastion.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetSessionKeyDetail {
    /**
     * @return The public key in OpenSSH format of the SSH key pair for the session. When you connect to the session, you must provide the private key of the same SSH key pair.
     * 
     */
    private final String publicKeyContent;

    @CustomType.Constructor
    private GetSessionKeyDetail(@CustomType.Parameter("publicKeyContent") String publicKeyContent) {
        this.publicKeyContent = publicKeyContent;
    }

    /**
     * @return The public key in OpenSSH format of the SSH key pair for the session. When you connect to the session, you must provide the private key of the same SSH key pair.
     * 
     */
    public String publicKeyContent() {
        return this.publicKeyContent;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSessionKeyDetail defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String publicKeyContent;

        public Builder() {
    	      // Empty
        }

        public Builder(GetSessionKeyDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.publicKeyContent = defaults.publicKeyContent;
        }

        public Builder publicKeyContent(String publicKeyContent) {
            this.publicKeyContent = Objects.requireNonNull(publicKeyContent);
            return this;
        }        public GetSessionKeyDetail build() {
            return new GetSessionKeyDetail(publicKeyContent);
        }
    }
}

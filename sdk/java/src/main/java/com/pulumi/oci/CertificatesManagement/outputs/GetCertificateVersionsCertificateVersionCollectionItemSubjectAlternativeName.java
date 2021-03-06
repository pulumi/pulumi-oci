// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CertificatesManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetCertificateVersionsCertificateVersionCollectionItemSubjectAlternativeName {
    /**
     * @return The subject alternative name type. Currently only DNS domain or host names and IP addresses are supported.
     * 
     */
    private final String type;
    /**
     * @return The subject alternative name.
     * 
     */
    private final String value;

    @CustomType.Constructor
    private GetCertificateVersionsCertificateVersionCollectionItemSubjectAlternativeName(
        @CustomType.Parameter("type") String type,
        @CustomType.Parameter("value") String value) {
        this.type = type;
        this.value = value;
    }

    /**
     * @return The subject alternative name type. Currently only DNS domain or host names and IP addresses are supported.
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return The subject alternative name.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCertificateVersionsCertificateVersionCollectionItemSubjectAlternativeName defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String type;
        private String value;

        public Builder() {
    	      // Empty
        }

        public Builder(GetCertificateVersionsCertificateVersionCollectionItemSubjectAlternativeName defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.type = defaults.type;
    	      this.value = defaults.value;
        }

        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }        public GetCertificateVersionsCertificateVersionCollectionItemSubjectAlternativeName build() {
            return new GetCertificateVersionsCertificateVersionCollectionItemSubjectAlternativeName(type, value);
        }
    }
}

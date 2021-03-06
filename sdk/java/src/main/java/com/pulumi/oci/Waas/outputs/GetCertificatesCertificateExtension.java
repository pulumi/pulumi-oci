// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Waas.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetCertificatesCertificateExtension {
    /**
     * @return The critical flag of the extension. Critical extensions must be processed, non-critical extensions can be ignored.
     * 
     */
    private final Boolean isCritical;
    /**
     * @return The certificate extension name.
     * 
     */
    private final String name;
    /**
     * @return The certificate extension value.
     * 
     */
    private final String value;

    @CustomType.Constructor
    private GetCertificatesCertificateExtension(
        @CustomType.Parameter("isCritical") Boolean isCritical,
        @CustomType.Parameter("name") String name,
        @CustomType.Parameter("value") String value) {
        this.isCritical = isCritical;
        this.name = name;
        this.value = value;
    }

    /**
     * @return The critical flag of the extension. Critical extensions must be processed, non-critical extensions can be ignored.
     * 
     */
    public Boolean isCritical() {
        return this.isCritical;
    }
    /**
     * @return The certificate extension name.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return The certificate extension value.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCertificatesCertificateExtension defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Boolean isCritical;
        private String name;
        private String value;

        public Builder() {
    	      // Empty
        }

        public Builder(GetCertificatesCertificateExtension defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isCritical = defaults.isCritical;
    	      this.name = defaults.name;
    	      this.value = defaults.value;
        }

        public Builder isCritical(Boolean isCritical) {
            this.isCritical = Objects.requireNonNull(isCritical);
            return this;
        }
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }        public GetCertificatesCertificateExtension build() {
            return new GetCertificatesCertificateExtension(isCritical, name, value);
        }
    }
}

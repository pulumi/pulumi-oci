// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OspGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.OspGateway.outputs.GetAddressRuleTaxFieldFormat;
import com.pulumi.oci.OspGateway.outputs.GetAddressRuleTaxFieldLabel;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAddressRuleTaxField {
    /**
     * @return Format information
     * 
     */
    private List<GetAddressRuleTaxFieldFormat> formats;
    /**
     * @return The given field is requeired or not
     * 
     */
    private Boolean isRequired;
    /**
     * @return Label information
     * 
     */
    private List<GetAddressRuleTaxFieldLabel> labels;
    /**
     * @return Locale code (rfc4646 format) of a forced language (e.g.: jp addresses require jp always)
     * 
     */
    private String language;
    /**
     * @return The field name
     * 
     */
    private String name;

    private GetAddressRuleTaxField() {}
    /**
     * @return Format information
     * 
     */
    public List<GetAddressRuleTaxFieldFormat> formats() {
        return this.formats;
    }
    /**
     * @return The given field is requeired or not
     * 
     */
    public Boolean isRequired() {
        return this.isRequired;
    }
    /**
     * @return Label information
     * 
     */
    public List<GetAddressRuleTaxFieldLabel> labels() {
        return this.labels;
    }
    /**
     * @return Locale code (rfc4646 format) of a forced language (e.g.: jp addresses require jp always)
     * 
     */
    public String language() {
        return this.language;
    }
    /**
     * @return The field name
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAddressRuleTaxField defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetAddressRuleTaxFieldFormat> formats;
        private Boolean isRequired;
        private List<GetAddressRuleTaxFieldLabel> labels;
        private String language;
        private String name;
        public Builder() {}
        public Builder(GetAddressRuleTaxField defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.formats = defaults.formats;
    	      this.isRequired = defaults.isRequired;
    	      this.labels = defaults.labels;
    	      this.language = defaults.language;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder formats(List<GetAddressRuleTaxFieldFormat> formats) {
            this.formats = Objects.requireNonNull(formats);
            return this;
        }
        public Builder formats(GetAddressRuleTaxFieldFormat... formats) {
            return formats(List.of(formats));
        }
        @CustomType.Setter
        public Builder isRequired(Boolean isRequired) {
            this.isRequired = Objects.requireNonNull(isRequired);
            return this;
        }
        @CustomType.Setter
        public Builder labels(List<GetAddressRuleTaxFieldLabel> labels) {
            this.labels = Objects.requireNonNull(labels);
            return this;
        }
        public Builder labels(GetAddressRuleTaxFieldLabel... labels) {
            return labels(List.of(labels));
        }
        @CustomType.Setter
        public Builder language(String language) {
            this.language = Objects.requireNonNull(language);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public GetAddressRuleTaxField build() {
            final var o = new GetAddressRuleTaxField();
            o.formats = formats;
            o.isRequired = isRequired;
            o.labels = labels;
            o.language = language;
            o.name = name;
            return o;
        }
    }
}
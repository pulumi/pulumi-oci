// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsSecurityQuestionsSecurityQuestionQuestionText {
    /**
     * @return If true, specifies that the localized attribute instance value is the default and will be returned if no localized value found for requesting user&#39;s preferred locale. One and only one instance should have this attribute set to true.
     * 
     */
    private Boolean default_;
    /**
     * @return The locale
     * 
     */
    private String locale;
    /**
     * @return Value of the tag.
     * 
     */
    private String value;

    private GetDomainsSecurityQuestionsSecurityQuestionQuestionText() {}
    /**
     * @return If true, specifies that the localized attribute instance value is the default and will be returned if no localized value found for requesting user&#39;s preferred locale. One and only one instance should have this attribute set to true.
     * 
     */
    public Boolean default_() {
        return this.default_;
    }
    /**
     * @return The locale
     * 
     */
    public String locale() {
        return this.locale;
    }
    /**
     * @return Value of the tag.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsSecurityQuestionsSecurityQuestionQuestionText defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean default_;
        private String locale;
        private String value;
        public Builder() {}
        public Builder(GetDomainsSecurityQuestionsSecurityQuestionQuestionText defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.default_ = defaults.default_;
    	      this.locale = defaults.locale;
    	      this.value = defaults.value;
        }

        @CustomType.Setter("default")
        public Builder default_(Boolean default_) {
            this.default_ = Objects.requireNonNull(default_);
            return this;
        }
        @CustomType.Setter
        public Builder locale(String locale) {
            this.locale = Objects.requireNonNull(locale);
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            this.value = Objects.requireNonNull(value);
            return this;
        }
        public GetDomainsSecurityQuestionsSecurityQuestionQuestionText build() {
            final var o = new GetDomainsSecurityQuestionsSecurityQuestionQuestionText();
            o.default_ = default_;
            o.locale = locale;
            o.value = value;
            return o;
        }
    }
}
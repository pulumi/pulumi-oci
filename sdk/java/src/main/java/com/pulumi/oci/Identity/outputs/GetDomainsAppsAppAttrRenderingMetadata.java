// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsAppsAppAttrRenderingMetadata {
    /**
     * @return Data type of the attribute.
     * 
     */
    private String datatype;
    /**
     * @return Help text for the attribute. It can contain HTML tags.
     * 
     */
    private String helptext;
    /**
     * @return Label for the attribute to be shown in the UI.
     * 
     */
    private String label;
    /**
     * @return Maximum length of the attribute.
     * 
     */
    private Integer maxLength;
    /**
     * @return Maximum size of the attribute.
     * 
     */
    private Integer maxSize;
    /**
     * @return Minimum length of the attribute.
     * 
     */
    private Integer minLength;
    /**
     * @return Minimum size of the attribute..
     * 
     */
    private Integer minSize;
    /**
     * @return The attribute represents the name of the attribute that will be used in the Security Assertion Markup Language (SAML) assertion
     * 
     */
    private String name;
    /**
     * @return Display sequence of the bundle configuration property.
     * 
     */
    private Integer order;
    /**
     * @return If true, indicates that this value must be protected.
     * 
     */
    private Boolean readOnly;
    /**
     * @return Regular expression of the attribute for validation.
     * 
     */
    private String regexp;
    /**
     * @return If true, this flatfile bundle configuration property is required to connect to the target connected managed app. This attribute maps to \&#34;isRequired\&#34; attribute in \&#34;ConfigurationProperty\&#34; in ICF.
     * 
     */
    private Boolean required;
    /**
     * @return UI widget to use for the attribute.
     * 
     */
    private String section;
    /**
     * @return Indicates whether the attribute is to be shown on the application creation UI.
     * 
     */
    private Boolean visible;
    /**
     * @return UI widget to use for the attribute.
     * 
     */
    private String widget;

    private GetDomainsAppsAppAttrRenderingMetadata() {}
    /**
     * @return Data type of the attribute.
     * 
     */
    public String datatype() {
        return this.datatype;
    }
    /**
     * @return Help text for the attribute. It can contain HTML tags.
     * 
     */
    public String helptext() {
        return this.helptext;
    }
    /**
     * @return Label for the attribute to be shown in the UI.
     * 
     */
    public String label() {
        return this.label;
    }
    /**
     * @return Maximum length of the attribute.
     * 
     */
    public Integer maxLength() {
        return this.maxLength;
    }
    /**
     * @return Maximum size of the attribute.
     * 
     */
    public Integer maxSize() {
        return this.maxSize;
    }
    /**
     * @return Minimum length of the attribute.
     * 
     */
    public Integer minLength() {
        return this.minLength;
    }
    /**
     * @return Minimum size of the attribute..
     * 
     */
    public Integer minSize() {
        return this.minSize;
    }
    /**
     * @return The attribute represents the name of the attribute that will be used in the Security Assertion Markup Language (SAML) assertion
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Display sequence of the bundle configuration property.
     * 
     */
    public Integer order() {
        return this.order;
    }
    /**
     * @return If true, indicates that this value must be protected.
     * 
     */
    public Boolean readOnly() {
        return this.readOnly;
    }
    /**
     * @return Regular expression of the attribute for validation.
     * 
     */
    public String regexp() {
        return this.regexp;
    }
    /**
     * @return If true, this flatfile bundle configuration property is required to connect to the target connected managed app. This attribute maps to \&#34;isRequired\&#34; attribute in \&#34;ConfigurationProperty\&#34; in ICF.
     * 
     */
    public Boolean required() {
        return this.required;
    }
    /**
     * @return UI widget to use for the attribute.
     * 
     */
    public String section() {
        return this.section;
    }
    /**
     * @return Indicates whether the attribute is to be shown on the application creation UI.
     * 
     */
    public Boolean visible() {
        return this.visible;
    }
    /**
     * @return UI widget to use for the attribute.
     * 
     */
    public String widget() {
        return this.widget;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsAppsAppAttrRenderingMetadata defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String datatype;
        private String helptext;
        private String label;
        private Integer maxLength;
        private Integer maxSize;
        private Integer minLength;
        private Integer minSize;
        private String name;
        private Integer order;
        private Boolean readOnly;
        private String regexp;
        private Boolean required;
        private String section;
        private Boolean visible;
        private String widget;
        public Builder() {}
        public Builder(GetDomainsAppsAppAttrRenderingMetadata defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.datatype = defaults.datatype;
    	      this.helptext = defaults.helptext;
    	      this.label = defaults.label;
    	      this.maxLength = defaults.maxLength;
    	      this.maxSize = defaults.maxSize;
    	      this.minLength = defaults.minLength;
    	      this.minSize = defaults.minSize;
    	      this.name = defaults.name;
    	      this.order = defaults.order;
    	      this.readOnly = defaults.readOnly;
    	      this.regexp = defaults.regexp;
    	      this.required = defaults.required;
    	      this.section = defaults.section;
    	      this.visible = defaults.visible;
    	      this.widget = defaults.widget;
        }

        @CustomType.Setter
        public Builder datatype(String datatype) {
            this.datatype = Objects.requireNonNull(datatype);
            return this;
        }
        @CustomType.Setter
        public Builder helptext(String helptext) {
            this.helptext = Objects.requireNonNull(helptext);
            return this;
        }
        @CustomType.Setter
        public Builder label(String label) {
            this.label = Objects.requireNonNull(label);
            return this;
        }
        @CustomType.Setter
        public Builder maxLength(Integer maxLength) {
            this.maxLength = Objects.requireNonNull(maxLength);
            return this;
        }
        @CustomType.Setter
        public Builder maxSize(Integer maxSize) {
            this.maxSize = Objects.requireNonNull(maxSize);
            return this;
        }
        @CustomType.Setter
        public Builder minLength(Integer minLength) {
            this.minLength = Objects.requireNonNull(minLength);
            return this;
        }
        @CustomType.Setter
        public Builder minSize(Integer minSize) {
            this.minSize = Objects.requireNonNull(minSize);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        @CustomType.Setter
        public Builder order(Integer order) {
            this.order = Objects.requireNonNull(order);
            return this;
        }
        @CustomType.Setter
        public Builder readOnly(Boolean readOnly) {
            this.readOnly = Objects.requireNonNull(readOnly);
            return this;
        }
        @CustomType.Setter
        public Builder regexp(String regexp) {
            this.regexp = Objects.requireNonNull(regexp);
            return this;
        }
        @CustomType.Setter
        public Builder required(Boolean required) {
            this.required = Objects.requireNonNull(required);
            return this;
        }
        @CustomType.Setter
        public Builder section(String section) {
            this.section = Objects.requireNonNull(section);
            return this;
        }
        @CustomType.Setter
        public Builder visible(Boolean visible) {
            this.visible = Objects.requireNonNull(visible);
            return this;
        }
        @CustomType.Setter
        public Builder widget(String widget) {
            this.widget = Objects.requireNonNull(widget);
            return this;
        }
        public GetDomainsAppsAppAttrRenderingMetadata build() {
            final var o = new GetDomainsAppsAppAttrRenderingMetadata();
            o.datatype = datatype;
            o.helptext = helptext;
            o.label = label;
            o.maxLength = maxLength;
            o.maxSize = maxSize;
            o.minLength = minLength;
            o.minSize = minSize;
            o.name = name;
            o.order = order;
            o.readOnly = readOnly;
            o.regexp = regexp;
            o.required = required;
            o.section = section;
            o.visible = visible;
            o.widget = widget;
            return o;
        }
    }
}
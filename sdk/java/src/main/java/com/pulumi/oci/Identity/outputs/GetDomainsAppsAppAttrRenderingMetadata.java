// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
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
            if (datatype == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppAttrRenderingMetadata", "datatype");
            }
            this.datatype = datatype;
            return this;
        }
        @CustomType.Setter
        public Builder helptext(String helptext) {
            if (helptext == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppAttrRenderingMetadata", "helptext");
            }
            this.helptext = helptext;
            return this;
        }
        @CustomType.Setter
        public Builder label(String label) {
            if (label == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppAttrRenderingMetadata", "label");
            }
            this.label = label;
            return this;
        }
        @CustomType.Setter
        public Builder maxLength(Integer maxLength) {
            if (maxLength == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppAttrRenderingMetadata", "maxLength");
            }
            this.maxLength = maxLength;
            return this;
        }
        @CustomType.Setter
        public Builder maxSize(Integer maxSize) {
            if (maxSize == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppAttrRenderingMetadata", "maxSize");
            }
            this.maxSize = maxSize;
            return this;
        }
        @CustomType.Setter
        public Builder minLength(Integer minLength) {
            if (minLength == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppAttrRenderingMetadata", "minLength");
            }
            this.minLength = minLength;
            return this;
        }
        @CustomType.Setter
        public Builder minSize(Integer minSize) {
            if (minSize == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppAttrRenderingMetadata", "minSize");
            }
            this.minSize = minSize;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppAttrRenderingMetadata", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder order(Integer order) {
            if (order == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppAttrRenderingMetadata", "order");
            }
            this.order = order;
            return this;
        }
        @CustomType.Setter
        public Builder readOnly(Boolean readOnly) {
            if (readOnly == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppAttrRenderingMetadata", "readOnly");
            }
            this.readOnly = readOnly;
            return this;
        }
        @CustomType.Setter
        public Builder regexp(String regexp) {
            if (regexp == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppAttrRenderingMetadata", "regexp");
            }
            this.regexp = regexp;
            return this;
        }
        @CustomType.Setter
        public Builder required(Boolean required) {
            if (required == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppAttrRenderingMetadata", "required");
            }
            this.required = required;
            return this;
        }
        @CustomType.Setter
        public Builder section(String section) {
            if (section == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppAttrRenderingMetadata", "section");
            }
            this.section = section;
            return this;
        }
        @CustomType.Setter
        public Builder visible(Boolean visible) {
            if (visible == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppAttrRenderingMetadata", "visible");
            }
            this.visible = visible;
            return this;
        }
        @CustomType.Setter
        public Builder widget(String widget) {
            if (widget == null) {
              throw new MissingRequiredPropertyException("GetDomainsAppsAppAttrRenderingMetadata", "widget");
            }
            this.widget = widget;
            return this;
        }
        public GetDomainsAppsAppAttrRenderingMetadata build() {
            final var _resultValue = new GetDomainsAppsAppAttrRenderingMetadata();
            _resultValue.datatype = datatype;
            _resultValue.helptext = helptext;
            _resultValue.label = label;
            _resultValue.maxLength = maxLength;
            _resultValue.maxSize = maxSize;
            _resultValue.minLength = minLength;
            _resultValue.minSize = minSize;
            _resultValue.name = name;
            _resultValue.order = order;
            _resultValue.readOnly = readOnly;
            _resultValue.regexp = regexp;
            _resultValue.required = required;
            _resultValue.section = section;
            _resultValue.visible = visible;
            _resultValue.widget = widget;
            return _resultValue;
        }
    }
}

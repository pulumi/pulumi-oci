// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Opsi.outputs.GetOpsiConfigurationConfigurationItemConfigItemMetadata;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetOpsiConfigurationConfigurationItemConfigItem {
    /**
     * @return List of contexts in Operations Insights where this configuration item is applicable.
     * 
     */
    private List<String> applicableContexts;
    /**
     * @return Type of configuration item.
     * 
     */
    private String configItemType;
    /**
     * @return Value of configuration item.
     * 
     */
    private String defaultValue;
    /**
     * @return Configuration item metadata.
     * 
     */
    private List<GetOpsiConfigurationConfigurationItemConfigItemMetadata> metadatas;
    /**
     * @return A filter to return only configuration items that match the entire name.
     * 
     */
    private String name;
    /**
     * @return Value of configuration item.
     * 
     */
    private String value;
    /**
     * @return Source configuration from where the value is taken for a configuration item.
     * 
     */
    private String valueSourceConfig;

    private GetOpsiConfigurationConfigurationItemConfigItem() {}
    /**
     * @return List of contexts in Operations Insights where this configuration item is applicable.
     * 
     */
    public List<String> applicableContexts() {
        return this.applicableContexts;
    }
    /**
     * @return Type of configuration item.
     * 
     */
    public String configItemType() {
        return this.configItemType;
    }
    /**
     * @return Value of configuration item.
     * 
     */
    public String defaultValue() {
        return this.defaultValue;
    }
    /**
     * @return Configuration item metadata.
     * 
     */
    public List<GetOpsiConfigurationConfigurationItemConfigItemMetadata> metadatas() {
        return this.metadatas;
    }
    /**
     * @return A filter to return only configuration items that match the entire name.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return Value of configuration item.
     * 
     */
    public String value() {
        return this.value;
    }
    /**
     * @return Source configuration from where the value is taken for a configuration item.
     * 
     */
    public String valueSourceConfig() {
        return this.valueSourceConfig;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOpsiConfigurationConfigurationItemConfigItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> applicableContexts;
        private String configItemType;
        private String defaultValue;
        private List<GetOpsiConfigurationConfigurationItemConfigItemMetadata> metadatas;
        private String name;
        private String value;
        private String valueSourceConfig;
        public Builder() {}
        public Builder(GetOpsiConfigurationConfigurationItemConfigItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicableContexts = defaults.applicableContexts;
    	      this.configItemType = defaults.configItemType;
    	      this.defaultValue = defaults.defaultValue;
    	      this.metadatas = defaults.metadatas;
    	      this.name = defaults.name;
    	      this.value = defaults.value;
    	      this.valueSourceConfig = defaults.valueSourceConfig;
        }

        @CustomType.Setter
        public Builder applicableContexts(List<String> applicableContexts) {
            if (applicableContexts == null) {
              throw new MissingRequiredPropertyException("GetOpsiConfigurationConfigurationItemConfigItem", "applicableContexts");
            }
            this.applicableContexts = applicableContexts;
            return this;
        }
        public Builder applicableContexts(String... applicableContexts) {
            return applicableContexts(List.of(applicableContexts));
        }
        @CustomType.Setter
        public Builder configItemType(String configItemType) {
            if (configItemType == null) {
              throw new MissingRequiredPropertyException("GetOpsiConfigurationConfigurationItemConfigItem", "configItemType");
            }
            this.configItemType = configItemType;
            return this;
        }
        @CustomType.Setter
        public Builder defaultValue(String defaultValue) {
            if (defaultValue == null) {
              throw new MissingRequiredPropertyException("GetOpsiConfigurationConfigurationItemConfigItem", "defaultValue");
            }
            this.defaultValue = defaultValue;
            return this;
        }
        @CustomType.Setter
        public Builder metadatas(List<GetOpsiConfigurationConfigurationItemConfigItemMetadata> metadatas) {
            if (metadatas == null) {
              throw new MissingRequiredPropertyException("GetOpsiConfigurationConfigurationItemConfigItem", "metadatas");
            }
            this.metadatas = metadatas;
            return this;
        }
        public Builder metadatas(GetOpsiConfigurationConfigurationItemConfigItemMetadata... metadatas) {
            return metadatas(List.of(metadatas));
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetOpsiConfigurationConfigurationItemConfigItem", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetOpsiConfigurationConfigurationItemConfigItem", "value");
            }
            this.value = value;
            return this;
        }
        @CustomType.Setter
        public Builder valueSourceConfig(String valueSourceConfig) {
            if (valueSourceConfig == null) {
              throw new MissingRequiredPropertyException("GetOpsiConfigurationConfigurationItemConfigItem", "valueSourceConfig");
            }
            this.valueSourceConfig = valueSourceConfig;
            return this;
        }
        public GetOpsiConfigurationConfigurationItemConfigItem build() {
            final var _resultValue = new GetOpsiConfigurationConfigurationItemConfigItem();
            _resultValue.applicableContexts = applicableContexts;
            _resultValue.configItemType = configItemType;
            _resultValue.defaultValue = defaultValue;
            _resultValue.metadatas = metadatas;
            _resultValue.name = name;
            _resultValue.value = value;
            _resultValue.valueSourceConfig = valueSourceConfig;
            return _resultValue;
        }
    }
}

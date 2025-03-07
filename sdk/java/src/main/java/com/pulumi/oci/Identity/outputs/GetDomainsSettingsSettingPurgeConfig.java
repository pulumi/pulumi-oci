// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsSettingsSettingPurgeConfig {
    /**
     * @return Resource Name
     * 
     */
    private String resourceName;
    /**
     * @return Retention Period
     * 
     */
    private Integer retentionPeriod;

    private GetDomainsSettingsSettingPurgeConfig() {}
    /**
     * @return Resource Name
     * 
     */
    public String resourceName() {
        return this.resourceName;
    }
    /**
     * @return Retention Period
     * 
     */
    public Integer retentionPeriod() {
        return this.retentionPeriod;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsSettingsSettingPurgeConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String resourceName;
        private Integer retentionPeriod;
        public Builder() {}
        public Builder(GetDomainsSettingsSettingPurgeConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.resourceName = defaults.resourceName;
    	      this.retentionPeriod = defaults.retentionPeriod;
        }

        @CustomType.Setter
        public Builder resourceName(String resourceName) {
            if (resourceName == null) {
              throw new MissingRequiredPropertyException("GetDomainsSettingsSettingPurgeConfig", "resourceName");
            }
            this.resourceName = resourceName;
            return this;
        }
        @CustomType.Setter
        public Builder retentionPeriod(Integer retentionPeriod) {
            if (retentionPeriod == null) {
              throw new MissingRequiredPropertyException("GetDomainsSettingsSettingPurgeConfig", "retentionPeriod");
            }
            this.retentionPeriod = retentionPeriod;
            return this;
        }
        public GetDomainsSettingsSettingPurgeConfig build() {
            final var _resultValue = new GetDomainsSettingsSettingPurgeConfig();
            _resultValue.resourceName = resourceName;
            _resultValue.retentionPeriod = retentionPeriod;
            return _resultValue;
        }
    }
}

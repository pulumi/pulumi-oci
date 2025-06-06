// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetInstanceConfigurationInstanceDetailOptionBlockVolumeCreateDetailBlockVolumeReplica {
    /**
     * @return The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
     * 
     */
    private String availabilityDomain;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private String displayName;

    private GetInstanceConfigurationInstanceDetailOptionBlockVolumeCreateDetailBlockVolumeReplica() {}
    /**
     * @return The availability domain of the instance.  Example: `Uocm:PHX-AD-1`
     * 
     */
    public String availabilityDomain() {
        return this.availabilityDomain;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstanceConfigurationInstanceDetailOptionBlockVolumeCreateDetailBlockVolumeReplica defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String availabilityDomain;
        private String displayName;
        public Builder() {}
        public Builder(GetInstanceConfigurationInstanceDetailOptionBlockVolumeCreateDetailBlockVolumeReplica defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.availabilityDomain = defaults.availabilityDomain;
    	      this.displayName = defaults.displayName;
        }

        @CustomType.Setter
        public Builder availabilityDomain(String availabilityDomain) {
            if (availabilityDomain == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationInstanceDetailOptionBlockVolumeCreateDetailBlockVolumeReplica", "availabilityDomain");
            }
            this.availabilityDomain = availabilityDomain;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetInstanceConfigurationInstanceDetailOptionBlockVolumeCreateDetailBlockVolumeReplica", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        public GetInstanceConfigurationInstanceDetailOptionBlockVolumeCreateDetailBlockVolumeReplica build() {
            final var _resultValue = new GetInstanceConfigurationInstanceDetailOptionBlockVolumeCreateDetailBlockVolumeReplica();
            _resultValue.availabilityDomain = availabilityDomain;
            _resultValue.displayName = displayName;
            return _resultValue;
        }
    }
}

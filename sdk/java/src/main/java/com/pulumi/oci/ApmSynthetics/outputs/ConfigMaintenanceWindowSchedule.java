// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ConfigMaintenanceWindowSchedule {
    /**
     * @return (Updatable) End time for the maintenance window, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     * 
     */
    private @Nullable String timeEnded;
    /**
     * @return (Updatable) Start time for the maintenance window, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     * 
     */
    private @Nullable String timeStarted;

    private ConfigMaintenanceWindowSchedule() {}
    /**
     * @return (Updatable) End time for the maintenance window, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     * 
     */
    public Optional<String> timeEnded() {
        return Optional.ofNullable(this.timeEnded);
    }
    /**
     * @return (Updatable) Start time for the maintenance window, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2020-02-12T22:47:12.613Z`
     * 
     */
    public Optional<String> timeStarted() {
        return Optional.ofNullable(this.timeStarted);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ConfigMaintenanceWindowSchedule defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String timeEnded;
        private @Nullable String timeStarted;
        public Builder() {}
        public Builder(ConfigMaintenanceWindowSchedule defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.timeEnded = defaults.timeEnded;
    	      this.timeStarted = defaults.timeStarted;
        }

        @CustomType.Setter
        public Builder timeEnded(@Nullable String timeEnded) {
            this.timeEnded = timeEnded;
            return this;
        }
        @CustomType.Setter
        public Builder timeStarted(@Nullable String timeStarted) {
            this.timeStarted = timeStarted;
            return this;
        }
        public ConfigMaintenanceWindowSchedule build() {
            final var o = new ConfigMaintenanceWindowSchedule();
            o.timeEnded = timeEnded;
            o.timeStarted = timeStarted;
            return o;
        }
    }
}
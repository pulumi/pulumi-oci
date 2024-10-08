// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ActionCreateZoneFromZoneFileNameserver {
    /**
     * @return The hostname of the nameserver.
     * 
     */
    private @Nullable String hostname;

    private ActionCreateZoneFromZoneFileNameserver() {}
    /**
     * @return The hostname of the nameserver.
     * 
     */
    public Optional<String> hostname() {
        return Optional.ofNullable(this.hostname);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ActionCreateZoneFromZoneFileNameserver defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String hostname;
        public Builder() {}
        public Builder(ActionCreateZoneFromZoneFileNameserver defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.hostname = defaults.hostname;
        }

        @CustomType.Setter
        public Builder hostname(@Nullable String hostname) {

            this.hostname = hostname;
            return this;
        }
        public ActionCreateZoneFromZoneFileNameserver build() {
            final var _resultValue = new ActionCreateZoneFromZoneFileNameserver();
            _resultValue.hostname = hostname;
            return _resultValue;
        }
    }
}

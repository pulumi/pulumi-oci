// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ActionCreateZoneFromZoneFileDnssecConfigKskDnssecKeyVersionDsData {
    private @Nullable String digestType;
    private @Nullable String rdata;

    private ActionCreateZoneFromZoneFileDnssecConfigKskDnssecKeyVersionDsData() {}
    public Optional<String> digestType() {
        return Optional.ofNullable(this.digestType);
    }
    public Optional<String> rdata() {
        return Optional.ofNullable(this.rdata);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ActionCreateZoneFromZoneFileDnssecConfigKskDnssecKeyVersionDsData defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String digestType;
        private @Nullable String rdata;
        public Builder() {}
        public Builder(ActionCreateZoneFromZoneFileDnssecConfigKskDnssecKeyVersionDsData defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.digestType = defaults.digestType;
    	      this.rdata = defaults.rdata;
        }

        @CustomType.Setter
        public Builder digestType(@Nullable String digestType) {

            this.digestType = digestType;
            return this;
        }
        @CustomType.Setter
        public Builder rdata(@Nullable String rdata) {

            this.rdata = rdata;
            return this;
        }
        public ActionCreateZoneFromZoneFileDnssecConfigKskDnssecKeyVersionDsData build() {
            final var _resultValue = new ActionCreateZoneFromZoneFileDnssecConfigKskDnssecKeyVersionDsData();
            _resultValue.digestType = digestType;
            _resultValue.rdata = rdata;
            return _resultValue;
        }
    }
}

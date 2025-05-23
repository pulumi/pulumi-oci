// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Dns.outputs.ZoneDnssecConfigKskDnssecKeyVersion;
import com.pulumi.oci.Dns.outputs.ZoneDnssecConfigZskDnssecKeyVersion;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class ZoneDnssecConfig {
    /**
     * @return A read-only array of key signing key (KSK) versions.
     * 
     */
    private @Nullable List<ZoneDnssecConfigKskDnssecKeyVersion> kskDnssecKeyVersions;
    /**
     * @return A read-only array of zone signing key (ZSK) versions.
     * 
     */
    private @Nullable List<ZoneDnssecConfigZskDnssecKeyVersion> zskDnssecKeyVersions;

    private ZoneDnssecConfig() {}
    /**
     * @return A read-only array of key signing key (KSK) versions.
     * 
     */
    public List<ZoneDnssecConfigKskDnssecKeyVersion> kskDnssecKeyVersions() {
        return this.kskDnssecKeyVersions == null ? List.of() : this.kskDnssecKeyVersions;
    }
    /**
     * @return A read-only array of zone signing key (ZSK) versions.
     * 
     */
    public List<ZoneDnssecConfigZskDnssecKeyVersion> zskDnssecKeyVersions() {
        return this.zskDnssecKeyVersions == null ? List.of() : this.zskDnssecKeyVersions;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ZoneDnssecConfig defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<ZoneDnssecConfigKskDnssecKeyVersion> kskDnssecKeyVersions;
        private @Nullable List<ZoneDnssecConfigZskDnssecKeyVersion> zskDnssecKeyVersions;
        public Builder() {}
        public Builder(ZoneDnssecConfig defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.kskDnssecKeyVersions = defaults.kskDnssecKeyVersions;
    	      this.zskDnssecKeyVersions = defaults.zskDnssecKeyVersions;
        }

        @CustomType.Setter
        public Builder kskDnssecKeyVersions(@Nullable List<ZoneDnssecConfigKskDnssecKeyVersion> kskDnssecKeyVersions) {

            this.kskDnssecKeyVersions = kskDnssecKeyVersions;
            return this;
        }
        public Builder kskDnssecKeyVersions(ZoneDnssecConfigKskDnssecKeyVersion... kskDnssecKeyVersions) {
            return kskDnssecKeyVersions(List.of(kskDnssecKeyVersions));
        }
        @CustomType.Setter
        public Builder zskDnssecKeyVersions(@Nullable List<ZoneDnssecConfigZskDnssecKeyVersion> zskDnssecKeyVersions) {

            this.zskDnssecKeyVersions = zskDnssecKeyVersions;
            return this;
        }
        public Builder zskDnssecKeyVersions(ZoneDnssecConfigZskDnssecKeyVersion... zskDnssecKeyVersions) {
            return zskDnssecKeyVersions(List.of(zskDnssecKeyVersions));
        }
        public ZoneDnssecConfig build() {
            final var _resultValue = new ZoneDnssecConfig();
            _resultValue.kskDnssecKeyVersions = kskDnssecKeyVersions;
            _resultValue.zskDnssecKeyVersions = zskDnssecKeyVersions;
            return _resultValue;
        }
    }
}

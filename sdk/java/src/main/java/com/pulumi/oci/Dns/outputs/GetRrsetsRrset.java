// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Dns.outputs.GetRrsetsRrsetItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetRrsetsRrset {
    /**
     * @return The target fully-qualified domain name (FQDN) within the target zone.
     * 
     */
    private String domain;
    private List<GetRrsetsRrsetItem> items;
    /**
     * @return Search by record type. Will match any record whose [type](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4) (case-insensitive) equals the provided value.
     * 
     */
    private String rtype;

    private GetRrsetsRrset() {}
    /**
     * @return The target fully-qualified domain name (FQDN) within the target zone.
     * 
     */
    public String domain() {
        return this.domain;
    }
    public List<GetRrsetsRrsetItem> items() {
        return this.items;
    }
    /**
     * @return Search by record type. Will match any record whose [type](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4) (case-insensitive) equals the provided value.
     * 
     */
    public String rtype() {
        return this.rtype;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRrsetsRrset defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String domain;
        private List<GetRrsetsRrsetItem> items;
        private String rtype;
        public Builder() {}
        public Builder(GetRrsetsRrset defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.domain = defaults.domain;
    	      this.items = defaults.items;
    	      this.rtype = defaults.rtype;
        }

        @CustomType.Setter
        public Builder domain(String domain) {
            if (domain == null) {
              throw new MissingRequiredPropertyException("GetRrsetsRrset", "domain");
            }
            this.domain = domain;
            return this;
        }
        @CustomType.Setter
        public Builder items(List<GetRrsetsRrsetItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetRrsetsRrset", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetRrsetsRrsetItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder rtype(String rtype) {
            if (rtype == null) {
              throw new MissingRequiredPropertyException("GetRrsetsRrset", "rtype");
            }
            this.rtype = rtype;
            return this;
        }
        public GetRrsetsRrset build() {
            final var _resultValue = new GetRrsetsRrset();
            _resultValue.domain = domain;
            _resultValue.items = items;
            _resultValue.rtype = rtype;
            return _resultValue;
        }
    }
}

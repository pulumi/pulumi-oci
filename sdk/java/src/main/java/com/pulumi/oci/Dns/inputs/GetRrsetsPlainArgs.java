// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Dns.inputs.GetRrsetsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRrsetsPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRrsetsPlainArgs Empty = new GetRrsetsPlainArgs();

    /**
     * The target fully-qualified domain name (FQDN) within the target zone.
     * 
     */
    @Import(name="domain")
    private @Nullable String domain;

    /**
     * @return The target fully-qualified domain name (FQDN) within the target zone.
     * 
     */
    public Optional<String> domain() {
        return Optional.ofNullable(this.domain);
    }

    /**
     * Matches any rrset whose fully-qualified domain name (FQDN) contains the provided value.
     * 
     */
    @Import(name="domainContains")
    private @Nullable String domainContains;

    /**
     * @return Matches any rrset whose fully-qualified domain name (FQDN) contains the provided value.
     * 
     */
    public Optional<String> domainContains() {
        return Optional.ofNullable(this.domainContains);
    }

    @Import(name="filters")
    private @Nullable List<GetRrsetsFilter> filters;

    public Optional<List<GetRrsetsFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Search by record type. Will match any record whose [type](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4) (case-insensitive) equals the provided value.
     * 
     */
    @Import(name="rtype")
    private @Nullable String rtype;

    /**
     * @return Search by record type. Will match any record whose [type](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4) (case-insensitive) equals the provided value.
     * 
     */
    public Optional<String> rtype() {
        return Optional.ofNullable(this.rtype);
    }

    /**
     * Specifies to operate only on resources that have a matching DNS scope.
     * 
     */
    @Import(name="scope")
    private @Nullable String scope;

    /**
     * @return Specifies to operate only on resources that have a matching DNS scope.
     * 
     */
    public Optional<String> scope() {
        return Optional.ofNullable(this.scope);
    }

    /**
     * The OCID of the view the resource is associated with.
     * 
     */
    @Import(name="viewId")
    private @Nullable String viewId;

    /**
     * @return The OCID of the view the resource is associated with.
     * 
     */
    public Optional<String> viewId() {
        return Optional.ofNullable(this.viewId);
    }

    /**
     * The name or OCID of the target zone.
     * 
     */
    @Import(name="zoneNameOrId", required=true)
    private String zoneNameOrId;

    /**
     * @return The name or OCID of the target zone.
     * 
     */
    public String zoneNameOrId() {
        return this.zoneNameOrId;
    }

    private GetRrsetsPlainArgs() {}

    private GetRrsetsPlainArgs(GetRrsetsPlainArgs $) {
        this.domain = $.domain;
        this.domainContains = $.domainContains;
        this.filters = $.filters;
        this.rtype = $.rtype;
        this.scope = $.scope;
        this.viewId = $.viewId;
        this.zoneNameOrId = $.zoneNameOrId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRrsetsPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRrsetsPlainArgs $;

        public Builder() {
            $ = new GetRrsetsPlainArgs();
        }

        public Builder(GetRrsetsPlainArgs defaults) {
            $ = new GetRrsetsPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param domain The target fully-qualified domain name (FQDN) within the target zone.
         * 
         * @return builder
         * 
         */
        public Builder domain(@Nullable String domain) {
            $.domain = domain;
            return this;
        }

        /**
         * @param domainContains Matches any rrset whose fully-qualified domain name (FQDN) contains the provided value.
         * 
         * @return builder
         * 
         */
        public Builder domainContains(@Nullable String domainContains) {
            $.domainContains = domainContains;
            return this;
        }

        public Builder filters(@Nullable List<GetRrsetsFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetRrsetsFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param rtype Search by record type. Will match any record whose [type](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4) (case-insensitive) equals the provided value.
         * 
         * @return builder
         * 
         */
        public Builder rtype(@Nullable String rtype) {
            $.rtype = rtype;
            return this;
        }

        /**
         * @param scope Specifies to operate only on resources that have a matching DNS scope.
         * 
         * @return builder
         * 
         */
        public Builder scope(@Nullable String scope) {
            $.scope = scope;
            return this;
        }

        /**
         * @param viewId The OCID of the view the resource is associated with.
         * 
         * @return builder
         * 
         */
        public Builder viewId(@Nullable String viewId) {
            $.viewId = viewId;
            return this;
        }

        /**
         * @param zoneNameOrId The name or OCID of the target zone.
         * 
         * @return builder
         * 
         */
        public Builder zoneNameOrId(String zoneNameOrId) {
            $.zoneNameOrId = zoneNameOrId;
            return this;
        }

        public GetRrsetsPlainArgs build() {
            $.zoneNameOrId = Objects.requireNonNull($.zoneNameOrId, "expected parameter 'zoneNameOrId' to be non-null");
            return $;
        }
    }

}
// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.MeteringComputation.outputs.GetCustomTableSavedCustomTableGroupByTag;
import java.lang.Double;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetCustomTableSavedCustomTable {
    /**
     * @return The column groupBy key list. example: `[&#34;tagNamespace&#34;, &#34;tagKey&#34;, &#34;tagValue&#34;, &#34;service&#34;, &#34;skuName&#34;, &#34;skuPartNumber&#34;, &#34;unit&#34;, &#34;compartmentName&#34;, &#34;compartmentPath&#34;, &#34;compartmentId&#34;, &#34;platform&#34;, &#34;region&#34;, &#34;logicalAd&#34;, &#34;resourceId&#34;, &#34;tenantId&#34;, &#34;tenantName&#34;]`
     * 
     */
    private List<String> columnGroupBies;
    /**
     * @return The compartment depth level.
     * 
     */
    private Double compartmentDepth;
    /**
     * @return The name of the custom table.
     * 
     */
    private String displayName;
    /**
     * @return GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only one tag in the list is supported. For example: `[{&#34;namespace&#34;:&#34;oracle&#34;, &#34;key&#34;:&#34;createdBy&#34;]`
     * 
     */
    private List<GetCustomTableSavedCustomTableGroupByTag> groupByTags;
    /**
     * @return The row groupBy key list. example: `[&#34;tagNamespace&#34;, &#34;tagKey&#34;, &#34;tagValue&#34;, &#34;service&#34;, &#34;skuName&#34;, &#34;skuPartNumber&#34;, &#34;unit&#34;, &#34;compartmentName&#34;, &#34;compartmentPath&#34;, &#34;compartmentId&#34;, &#34;platform&#34;, &#34;region&#34;, &#34;logicalAd&#34;, &#34;resourceId&#34;, &#34;tenantId&#34;, &#34;tenantName&#34;]`
     * 
     */
    private List<String> rowGroupBies;
    /**
     * @return The version of the custom table.
     * 
     */
    private Double version;

    private GetCustomTableSavedCustomTable() {}
    /**
     * @return The column groupBy key list. example: `[&#34;tagNamespace&#34;, &#34;tagKey&#34;, &#34;tagValue&#34;, &#34;service&#34;, &#34;skuName&#34;, &#34;skuPartNumber&#34;, &#34;unit&#34;, &#34;compartmentName&#34;, &#34;compartmentPath&#34;, &#34;compartmentId&#34;, &#34;platform&#34;, &#34;region&#34;, &#34;logicalAd&#34;, &#34;resourceId&#34;, &#34;tenantId&#34;, &#34;tenantName&#34;]`
     * 
     */
    public List<String> columnGroupBies() {
        return this.columnGroupBies;
    }
    /**
     * @return The compartment depth level.
     * 
     */
    public Double compartmentDepth() {
        return this.compartmentDepth;
    }
    /**
     * @return The name of the custom table.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only one tag in the list is supported. For example: `[{&#34;namespace&#34;:&#34;oracle&#34;, &#34;key&#34;:&#34;createdBy&#34;]`
     * 
     */
    public List<GetCustomTableSavedCustomTableGroupByTag> groupByTags() {
        return this.groupByTags;
    }
    /**
     * @return The row groupBy key list. example: `[&#34;tagNamespace&#34;, &#34;tagKey&#34;, &#34;tagValue&#34;, &#34;service&#34;, &#34;skuName&#34;, &#34;skuPartNumber&#34;, &#34;unit&#34;, &#34;compartmentName&#34;, &#34;compartmentPath&#34;, &#34;compartmentId&#34;, &#34;platform&#34;, &#34;region&#34;, &#34;logicalAd&#34;, &#34;resourceId&#34;, &#34;tenantId&#34;, &#34;tenantName&#34;]`
     * 
     */
    public List<String> rowGroupBies() {
        return this.rowGroupBies;
    }
    /**
     * @return The version of the custom table.
     * 
     */
    public Double version() {
        return this.version;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCustomTableSavedCustomTable defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> columnGroupBies;
        private Double compartmentDepth;
        private String displayName;
        private List<GetCustomTableSavedCustomTableGroupByTag> groupByTags;
        private List<String> rowGroupBies;
        private Double version;
        public Builder() {}
        public Builder(GetCustomTableSavedCustomTable defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.columnGroupBies = defaults.columnGroupBies;
    	      this.compartmentDepth = defaults.compartmentDepth;
    	      this.displayName = defaults.displayName;
    	      this.groupByTags = defaults.groupByTags;
    	      this.rowGroupBies = defaults.rowGroupBies;
    	      this.version = defaults.version;
        }

        @CustomType.Setter
        public Builder columnGroupBies(List<String> columnGroupBies) {
            this.columnGroupBies = Objects.requireNonNull(columnGroupBies);
            return this;
        }
        public Builder columnGroupBies(String... columnGroupBies) {
            return columnGroupBies(List.of(columnGroupBies));
        }
        @CustomType.Setter
        public Builder compartmentDepth(Double compartmentDepth) {
            this.compartmentDepth = Objects.requireNonNull(compartmentDepth);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            this.displayName = Objects.requireNonNull(displayName);
            return this;
        }
        @CustomType.Setter
        public Builder groupByTags(List<GetCustomTableSavedCustomTableGroupByTag> groupByTags) {
            this.groupByTags = Objects.requireNonNull(groupByTags);
            return this;
        }
        public Builder groupByTags(GetCustomTableSavedCustomTableGroupByTag... groupByTags) {
            return groupByTags(List.of(groupByTags));
        }
        @CustomType.Setter
        public Builder rowGroupBies(List<String> rowGroupBies) {
            this.rowGroupBies = Objects.requireNonNull(rowGroupBies);
            return this;
        }
        public Builder rowGroupBies(String... rowGroupBies) {
            return rowGroupBies(List.of(rowGroupBies));
        }
        @CustomType.Setter
        public Builder version(Double version) {
            this.version = Objects.requireNonNull(version);
            return this;
        }
        public GetCustomTableSavedCustomTable build() {
            final var o = new GetCustomTableSavedCustomTable();
            o.columnGroupBies = columnGroupBies;
            o.compartmentDepth = compartmentDepth;
            o.displayName = displayName;
            o.groupByTags = groupByTags;
            o.rowGroupBies = rowGroupBies;
            o.version = version;
            return o;
        }
    }
}
// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.MeteringComputation.inputs.CustomTableSavedCustomTableGroupByTagArgs;
import java.lang.Double;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CustomTableSavedCustomTableArgs extends com.pulumi.resources.ResourceArgs {

    public static final CustomTableSavedCustomTableArgs Empty = new CustomTableSavedCustomTableArgs();

    /**
     * (Updatable) The column groupBy key list. example: `[&#34;tagNamespace&#34;, &#34;tagKey&#34;, &#34;tagValue&#34;, &#34;service&#34;, &#34;skuName&#34;, &#34;skuPartNumber&#34;, &#34;unit&#34;, &#34;compartmentName&#34;, &#34;compartmentPath&#34;, &#34;compartmentId&#34;, &#34;platform&#34;, &#34;region&#34;, &#34;logicalAd&#34;, &#34;resourceId&#34;, &#34;tenantId&#34;, &#34;tenantName&#34;]`
     * 
     */
    @Import(name="columnGroupBies")
    private @Nullable Output<List<String>> columnGroupBies;

    /**
     * @return (Updatable) The column groupBy key list. example: `[&#34;tagNamespace&#34;, &#34;tagKey&#34;, &#34;tagValue&#34;, &#34;service&#34;, &#34;skuName&#34;, &#34;skuPartNumber&#34;, &#34;unit&#34;, &#34;compartmentName&#34;, &#34;compartmentPath&#34;, &#34;compartmentId&#34;, &#34;platform&#34;, &#34;region&#34;, &#34;logicalAd&#34;, &#34;resourceId&#34;, &#34;tenantId&#34;, &#34;tenantName&#34;]`
     * 
     */
    public Optional<Output<List<String>>> columnGroupBies() {
        return Optional.ofNullable(this.columnGroupBies);
    }

    /**
     * (Updatable) The compartment depth level.
     * 
     */
    @Import(name="compartmentDepth")
    private @Nullable Output<Double> compartmentDepth;

    /**
     * @return (Updatable) The compartment depth level.
     * 
     */
    public Optional<Output<Double>> compartmentDepth() {
        return Optional.ofNullable(this.compartmentDepth);
    }

    /**
     * (Updatable) The name of the custom table.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) The name of the custom table.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only one tag in the list is supported. For example: `[{&#34;namespace&#34;:&#34;oracle&#34;, &#34;key&#34;:&#34;createdBy&#34;]`
     * 
     */
    @Import(name="groupByTags")
    private @Nullable Output<List<CustomTableSavedCustomTableGroupByTagArgs>> groupByTags;

    /**
     * @return (Updatable) GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only one tag in the list is supported. For example: `[{&#34;namespace&#34;:&#34;oracle&#34;, &#34;key&#34;:&#34;createdBy&#34;]`
     * 
     */
    public Optional<Output<List<CustomTableSavedCustomTableGroupByTagArgs>>> groupByTags() {
        return Optional.ofNullable(this.groupByTags);
    }

    /**
     * (Updatable) The row groupBy key list. example: `[&#34;tagNamespace&#34;, &#34;tagKey&#34;, &#34;tagValue&#34;, &#34;service&#34;, &#34;skuName&#34;, &#34;skuPartNumber&#34;, &#34;unit&#34;, &#34;compartmentName&#34;, &#34;compartmentPath&#34;, &#34;compartmentId&#34;, &#34;platform&#34;, &#34;region&#34;, &#34;logicalAd&#34;, &#34;resourceId&#34;, &#34;tenantId&#34;, &#34;tenantName&#34;]`
     * 
     */
    @Import(name="rowGroupBies")
    private @Nullable Output<List<String>> rowGroupBies;

    /**
     * @return (Updatable) The row groupBy key list. example: `[&#34;tagNamespace&#34;, &#34;tagKey&#34;, &#34;tagValue&#34;, &#34;service&#34;, &#34;skuName&#34;, &#34;skuPartNumber&#34;, &#34;unit&#34;, &#34;compartmentName&#34;, &#34;compartmentPath&#34;, &#34;compartmentId&#34;, &#34;platform&#34;, &#34;region&#34;, &#34;logicalAd&#34;, &#34;resourceId&#34;, &#34;tenantId&#34;, &#34;tenantName&#34;]`
     * 
     */
    public Optional<Output<List<String>>> rowGroupBies() {
        return Optional.ofNullable(this.rowGroupBies);
    }

    /**
     * (Updatable) The version of the custom table.
     * 
     */
    @Import(name="version")
    private @Nullable Output<Double> version;

    /**
     * @return (Updatable) The version of the custom table.
     * 
     */
    public Optional<Output<Double>> version() {
        return Optional.ofNullable(this.version);
    }

    private CustomTableSavedCustomTableArgs() {}

    private CustomTableSavedCustomTableArgs(CustomTableSavedCustomTableArgs $) {
        this.columnGroupBies = $.columnGroupBies;
        this.compartmentDepth = $.compartmentDepth;
        this.displayName = $.displayName;
        this.groupByTags = $.groupByTags;
        this.rowGroupBies = $.rowGroupBies;
        this.version = $.version;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CustomTableSavedCustomTableArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CustomTableSavedCustomTableArgs $;

        public Builder() {
            $ = new CustomTableSavedCustomTableArgs();
        }

        public Builder(CustomTableSavedCustomTableArgs defaults) {
            $ = new CustomTableSavedCustomTableArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param columnGroupBies (Updatable) The column groupBy key list. example: `[&#34;tagNamespace&#34;, &#34;tagKey&#34;, &#34;tagValue&#34;, &#34;service&#34;, &#34;skuName&#34;, &#34;skuPartNumber&#34;, &#34;unit&#34;, &#34;compartmentName&#34;, &#34;compartmentPath&#34;, &#34;compartmentId&#34;, &#34;platform&#34;, &#34;region&#34;, &#34;logicalAd&#34;, &#34;resourceId&#34;, &#34;tenantId&#34;, &#34;tenantName&#34;]`
         * 
         * @return builder
         * 
         */
        public Builder columnGroupBies(@Nullable Output<List<String>> columnGroupBies) {
            $.columnGroupBies = columnGroupBies;
            return this;
        }

        /**
         * @param columnGroupBies (Updatable) The column groupBy key list. example: `[&#34;tagNamespace&#34;, &#34;tagKey&#34;, &#34;tagValue&#34;, &#34;service&#34;, &#34;skuName&#34;, &#34;skuPartNumber&#34;, &#34;unit&#34;, &#34;compartmentName&#34;, &#34;compartmentPath&#34;, &#34;compartmentId&#34;, &#34;platform&#34;, &#34;region&#34;, &#34;logicalAd&#34;, &#34;resourceId&#34;, &#34;tenantId&#34;, &#34;tenantName&#34;]`
         * 
         * @return builder
         * 
         */
        public Builder columnGroupBies(List<String> columnGroupBies) {
            return columnGroupBies(Output.of(columnGroupBies));
        }

        /**
         * @param columnGroupBies (Updatable) The column groupBy key list. example: `[&#34;tagNamespace&#34;, &#34;tagKey&#34;, &#34;tagValue&#34;, &#34;service&#34;, &#34;skuName&#34;, &#34;skuPartNumber&#34;, &#34;unit&#34;, &#34;compartmentName&#34;, &#34;compartmentPath&#34;, &#34;compartmentId&#34;, &#34;platform&#34;, &#34;region&#34;, &#34;logicalAd&#34;, &#34;resourceId&#34;, &#34;tenantId&#34;, &#34;tenantName&#34;]`
         * 
         * @return builder
         * 
         */
        public Builder columnGroupBies(String... columnGroupBies) {
            return columnGroupBies(List.of(columnGroupBies));
        }

        /**
         * @param compartmentDepth (Updatable) The compartment depth level.
         * 
         * @return builder
         * 
         */
        public Builder compartmentDepth(@Nullable Output<Double> compartmentDepth) {
            $.compartmentDepth = compartmentDepth;
            return this;
        }

        /**
         * @param compartmentDepth (Updatable) The compartment depth level.
         * 
         * @return builder
         * 
         */
        public Builder compartmentDepth(Double compartmentDepth) {
            return compartmentDepth(Output.of(compartmentDepth));
        }

        /**
         * @param displayName (Updatable) The name of the custom table.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The name of the custom table.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param groupByTags (Updatable) GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only one tag in the list is supported. For example: `[{&#34;namespace&#34;:&#34;oracle&#34;, &#34;key&#34;:&#34;createdBy&#34;]`
         * 
         * @return builder
         * 
         */
        public Builder groupByTags(@Nullable Output<List<CustomTableSavedCustomTableGroupByTagArgs>> groupByTags) {
            $.groupByTags = groupByTags;
            return this;
        }

        /**
         * @param groupByTags (Updatable) GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only one tag in the list is supported. For example: `[{&#34;namespace&#34;:&#34;oracle&#34;, &#34;key&#34;:&#34;createdBy&#34;]`
         * 
         * @return builder
         * 
         */
        public Builder groupByTags(List<CustomTableSavedCustomTableGroupByTagArgs> groupByTags) {
            return groupByTags(Output.of(groupByTags));
        }

        /**
         * @param groupByTags (Updatable) GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only one tag in the list is supported. For example: `[{&#34;namespace&#34;:&#34;oracle&#34;, &#34;key&#34;:&#34;createdBy&#34;]`
         * 
         * @return builder
         * 
         */
        public Builder groupByTags(CustomTableSavedCustomTableGroupByTagArgs... groupByTags) {
            return groupByTags(List.of(groupByTags));
        }

        /**
         * @param rowGroupBies (Updatable) The row groupBy key list. example: `[&#34;tagNamespace&#34;, &#34;tagKey&#34;, &#34;tagValue&#34;, &#34;service&#34;, &#34;skuName&#34;, &#34;skuPartNumber&#34;, &#34;unit&#34;, &#34;compartmentName&#34;, &#34;compartmentPath&#34;, &#34;compartmentId&#34;, &#34;platform&#34;, &#34;region&#34;, &#34;logicalAd&#34;, &#34;resourceId&#34;, &#34;tenantId&#34;, &#34;tenantName&#34;]`
         * 
         * @return builder
         * 
         */
        public Builder rowGroupBies(@Nullable Output<List<String>> rowGroupBies) {
            $.rowGroupBies = rowGroupBies;
            return this;
        }

        /**
         * @param rowGroupBies (Updatable) The row groupBy key list. example: `[&#34;tagNamespace&#34;, &#34;tagKey&#34;, &#34;tagValue&#34;, &#34;service&#34;, &#34;skuName&#34;, &#34;skuPartNumber&#34;, &#34;unit&#34;, &#34;compartmentName&#34;, &#34;compartmentPath&#34;, &#34;compartmentId&#34;, &#34;platform&#34;, &#34;region&#34;, &#34;logicalAd&#34;, &#34;resourceId&#34;, &#34;tenantId&#34;, &#34;tenantName&#34;]`
         * 
         * @return builder
         * 
         */
        public Builder rowGroupBies(List<String> rowGroupBies) {
            return rowGroupBies(Output.of(rowGroupBies));
        }

        /**
         * @param rowGroupBies (Updatable) The row groupBy key list. example: `[&#34;tagNamespace&#34;, &#34;tagKey&#34;, &#34;tagValue&#34;, &#34;service&#34;, &#34;skuName&#34;, &#34;skuPartNumber&#34;, &#34;unit&#34;, &#34;compartmentName&#34;, &#34;compartmentPath&#34;, &#34;compartmentId&#34;, &#34;platform&#34;, &#34;region&#34;, &#34;logicalAd&#34;, &#34;resourceId&#34;, &#34;tenantId&#34;, &#34;tenantName&#34;]`
         * 
         * @return builder
         * 
         */
        public Builder rowGroupBies(String... rowGroupBies) {
            return rowGroupBies(List.of(rowGroupBies));
        }

        /**
         * @param version (Updatable) The version of the custom table.
         * 
         * @return builder
         * 
         */
        public Builder version(@Nullable Output<Double> version) {
            $.version = version;
            return this;
        }

        /**
         * @param version (Updatable) The version of the custom table.
         * 
         * @return builder
         * 
         */
        public Builder version(Double version) {
            return version(Output.of(version));
        }

        public CustomTableSavedCustomTableArgs build() {
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            return $;
        }
    }

}
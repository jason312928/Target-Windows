using Xunit;

namespace Target.Windows.Tests;

public sealed class ProductInfoTests
{
    [Fact]
    public void ProductNameIsStable()
    {
        Assert.Equal("Target", Target.Windows.App.ProductInfo.Name);
    }
}

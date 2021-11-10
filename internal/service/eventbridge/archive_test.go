package eventbridge_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	events "github.com/aws/aws-sdk-go/service/eventbridge"
	sdkacctest "github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	tfeventbridge "github.com/hashicorp/terraform-provider-aws/internal/service/eventbridge"
)

func TestAccEventBridgeArchive_basic(t *testing.T) {
	var v1 events.DescribeArchiveOutput
	archiveName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_cloudwatch_event_archive.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t) },
		ErrorCheck:   acctest.ErrorCheck(t, events.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckArchiveDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccArchiveConfig(archiveName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckArchiveExists(resourceName, &v1),
					resource.TestCheckResourceAttr(resourceName, "name", archiveName),
					resource.TestCheckResourceAttr(resourceName, "retention_days", "0"),
					acctest.CheckResourceAttrRegionalARN(resourceName, "arn", "events", fmt.Sprintf("archive/%s", archiveName)),
					resource.TestCheckResourceAttr(resourceName, "description", ""),
					resource.TestCheckResourceAttr(resourceName, "event_pattern", ""),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccEventBridgeArchive_update(t *testing.T) {
	var v1 events.DescribeArchiveOutput
	resourceName := "aws_cloudwatch_event_archive.test"
	archiveName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t) },
		ErrorCheck:   acctest.ErrorCheck(t, events.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckArchiveDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccArchiveConfig(archiveName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckArchiveExists(resourceName, &v1),
				),
			},
			{
				Config: testAccArchiveConfig_updateAttributes(archiveName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckArchiveExists(resourceName, &v1),
					resource.TestCheckResourceAttr(resourceName, "retention_days", "7"),
					acctest.CheckResourceAttrEquivalentJSON(resourceName, "event_pattern", "{\"source\":[\"company.team.service\"]}"),
					resource.TestCheckResourceAttr(resourceName, "description", "test"),
				),
			},
		},
	})
}

func TestAccEventBridgeArchive_disappears(t *testing.T) {
	var v events.DescribeArchiveOutput
	archiveName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_cloudwatch_event_archive.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t) },
		ErrorCheck:   acctest.ErrorCheck(t, events.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckArchiveDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccArchiveConfig(archiveName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckArchiveExists(resourceName, &v),
					acctest.CheckResourceDisappears(acctest.Provider, tfeventbridge.ResourceArchive(), resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func testAccCheckArchiveDestroy(s *terraform.State) error {
	conn := acctest.Provider.Meta().(*conns.AWSClient).EventBridgeConn

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aws_cloudwatch_event_archive" {
			continue
		}

		params := events.DescribeArchiveInput{
			ArchiveName: aws.String(rs.Primary.ID),
		}

		resp, err := conn.DescribeArchive(&params)

		if err == nil {
			return fmt.Errorf("EventBridge event bus (%s) still exists: %s", rs.Primary.ID, resp)
		}
	}

	return nil
}

func testAccCheckArchiveExists(n string, v *events.DescribeArchiveOutput) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).EventBridgeConn
		params := events.DescribeArchiveInput{
			ArchiveName: aws.String(rs.Primary.ID),
		}

		resp, err := conn.DescribeArchive(&params)
		if err != nil {
			return err
		}

		if resp == nil {
			return fmt.Errorf("EventBridge archive (%s) not found", n)
		}

		*v = *resp

		return nil
	}
}

func TestAccEventBridgeArchive_retentionSetOnCreation(t *testing.T) {
	var v1 events.DescribeArchiveOutput
	archiveName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_cloudwatch_event_archive.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:     func() { acctest.PreCheck(t) },
		ErrorCheck:   acctest.ErrorCheck(t, events.EndpointsID),
		Providers:    acctest.Providers,
		CheckDestroy: testAccCheckArchiveDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccArchiveConfig_retentionOnCreation(archiveName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckArchiveExists(resourceName, &v1),
					resource.TestCheckResourceAttr(resourceName, "name", archiveName),
					resource.TestCheckResourceAttr(resourceName, "retention_days", "1"),
					acctest.CheckResourceAttrRegionalARN(resourceName, "arn", "events", fmt.Sprintf("archive/%s", archiveName)),
					resource.TestCheckResourceAttr(resourceName, "description", ""),
					resource.TestCheckResourceAttr(resourceName, "event_pattern", ""),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func testAccArchiveConfig(name string) string {
	return fmt.Sprintf(`
resource "aws_cloudwatch_event_bus" "test" {
  name = %[1]q
}

resource "aws_cloudwatch_event_archive" "test" {
  name             = %[1]q
  event_source_arn = aws_cloudwatch_event_bus.test.arn
}
`, name)
}

func testAccArchiveConfig_updateAttributes(name string) string {
	return fmt.Sprintf(`
resource "aws_cloudwatch_event_bus" "test" {
  name = %[1]q
}

resource "aws_cloudwatch_event_archive" "test" {
  name             = %[1]q
  event_source_arn = aws_cloudwatch_event_bus.test.arn
  retention_days   = 7
  description      = "test"
  event_pattern    = <<PATTERN
{
  "source": ["company.team.service"]
}
PATTERN
}
`, name)
}

func testAccArchiveConfig_retentionOnCreation(name string) string {
	return fmt.Sprintf(`
resource "aws_cloudwatch_event_bus" "test" {
  name = %[1]q
}

resource "aws_cloudwatch_event_archive" "test" {
  name             = %[1]q
  event_source_arn = aws_cloudwatch_event_bus.test.arn
  retention_days   = 1
}
`, name)
}

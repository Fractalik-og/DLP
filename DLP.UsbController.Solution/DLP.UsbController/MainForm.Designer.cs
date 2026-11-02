namespace DLP.UsbController
{
    partial class MainForm
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            components = new System.ComponentModel.Container();
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(1000, 640);
            Text = "DLP USB Analyzer";
            StartPosition = FormStartPosition.CenterScreen;

            // Порядок добавления важен для Dock: Fill раньше, чем Top/Lower.
            Controls.Add(_grid);       // Dock.Fill
            Controls.Add(_toolStrip);  // Dock.Top
            Controls.Add(_statusStrip);// Dock.Bottom
        }

        #endregion
    }
}
